-- 说明: sqlite_sequence 是 SQLite 为 AUTOINCREMENT 主键自动维护的内部表，
-- 不应在迁移脚本中手动创建/删除或修改。D1/SQLite 会在需要时自动生成。

-- 用户表 (Users Table)
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  two_factor_enabled INTEGER DEFAULT 0,
  two_factor_secret TEXT
);

-- 密码表 (Passwords Table)
DROP TABLE IF EXISTS passwords;

CREATE TABLE passwords (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  website TEXT NOT NULL,
  password TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  username TEXT DEFAULT "",
  tags TEXT DEFAULT ""
);

-- 恢复码表 (Recovery Codes Table for 2FA)
DROP TABLE IF EXISTS recovery_codes;

CREATE TABLE recovery_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  code_hash TEXT,
  used INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 索引 (Indexes)
CREATE INDEX idx_passwords_user_id ON passwords(user_id);
CREATE INDEX idx_recovery_user ON recovery_codes(user_id);