import os
import sqlite3
import time
from contextlib import closing

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
JWT_SECRET = os.environ.get("JWT_SECRET")

# 确保启动时设置了 JWT 密钥
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is required")

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# 1. 认证中间件（验证 JWT）
def token_required(func):
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify(error="missing or invalid Authorization header"), 401

        token = auth.split(" ", 1)[1]
        try:
            # 验证 JWT 签名和过期时间
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify(error="token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401

        g.user = payload["sub"]
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper

# 2. XSS 防护：对输出进行 HTML 转义
def sanitize(value):
    return str(escape(value))

# 3. 接口 1：用户登录（签发 JWT）
@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username or not password:
        return jsonify(error="username and password are required"), 400

    with closing(get_conn()) as conn:
        # SQLi 防护：使用参数化查询（? 占位符）
        row = conn.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row is None:
        return jsonify(error="invalid credentials"), 401

    # 安全校验：比对 bcrypt 哈希
    stored_hash = row["password_hash"].encode("utf-8")
    if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        return jsonify(error="invalid credentials"), 401

    # 签发有效期为 1 小时的 JWT
    now = int(time.time())
    token = jwt.encode(
        {"sub": row["username"], "iat": now, "exp": now + 3600},
        JWT_SECRET,
        algorithm="HS256",
    )
           # 推荐写法：直接写在行尾
    return jsonify(token=token, token_type="Bearer", expires_in=3600)  # nosec B106

# 4. 接口 2：获取数据（受保护）
@app.get("/api/data")
@token_required
def get_data():
    with closing(get_conn()) as conn:
        rows = conn.execute(
            "SELECT id, title, content, author, created_at FROM posts ORDER BY id DESC"
        ).fetchall()

    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "title": sanitize(row["title"]),       # 转义防 XSS
            "content": sanitize(row["content"]),   # 转义防 XSS
            "author": sanitize(row["author"]),
            "created_at": row["created_at"],
        })
    return jsonify(result)

# 5. 接口 3：创建帖子（受保护）
@app.post("/api/posts")
@token_required
def create_post():
    data = request.get_json(silent=True) or {}
    title = str(data.get("title", "")).strip()
    content = str(data.get("content", "")).strip()

    if not title or not content:
        return jsonify(error="title and content are required"), 400
    if len(title) > 200 or len(content) > 2000:
        return jsonify(error="title or content too long"), 400

    with closing(get_conn()) as conn:
        with conn:
            cur = conn.execute(
                "INSERT INTO posts (title, content, author) VALUES (?, ?, ?)",
                (title, content, g.user),
            )
            post_id = cur.lastrowid

    return jsonify(
        id=post_id,
        title=sanitize(title),
        content=sanitize(content),
        author=sanitize(g.user),
    ), 201

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)