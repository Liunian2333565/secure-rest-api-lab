import os
import sqlite3
import bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

def main():
    # 从环境变量获取密码，如果没设置，默认用 'Admin123!'
    admin_password = os.environ.get("ADMIN_PASSWORD", "Admin123!")
    
    # 用 bcrypt 对密码进行哈希加密
    password_hash = bcrypt.hashpw(
        admin_password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    conn = sqlite3.connect(DB_PATH)
    try:
        # 创建用户表
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        # 创建帖子表（用来测试 XSS 和数据获取）
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        # 插入默认管理员用户
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", password_hash),
        )
        conn.commit()
        print("Database initialized successfully. User: admin")
    finally:
        conn.close()

if __name__ == "__main__":
    main()