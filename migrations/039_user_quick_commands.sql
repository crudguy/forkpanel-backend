-- 用户级终端快捷命令（039）：按登录用户存储，跨设备同步。
-- 预置命令不入库（前端常量），这里只存用户自建项；user_id 外键随用户删除级联清理。
CREATE TABLE IF NOT EXISTS user_quick_commands (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label       TEXT NOT NULL,
    cmd         TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_quick_commands_user ON user_quick_commands(user_id);
