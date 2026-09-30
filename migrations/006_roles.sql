-- v6：自定义角色（RBAC）
--
-- 动机：内置四角色是"一刀切"的。真实运维里更常见的是"只让他管站点、别碰数据库"
-- 这类细分诉求，内置角色表达不了——用户只能发一个权限更大的角色（过度授予），
-- 或者干脆共用 owner 账号（更糟：没有可追溯性，审计里看不出谁干的）。
--
-- 设计取舍：
-- 1) **只存自定义角色**。内置四角色仍由代码定义（panel-api/src/auth.rs 的
--    permissions_for_role），不在库里再存一份——两处定义必然漂移，而权限判断
--    出错是要出安全事故的，不能有两份"事实"。
-- 2) 权限集合以 JSON 数组存储。校验有两层：必须在已知权限白名单内；且必须是
--    创建者**自身权限的子集**——没有第二条，拥有 user.manage 的人就能造出比
--    owner 还大的角色再把自己升上去。
-- 3) 内置角色名是保留字，自定义角色不得占用：同名两套权限是最难排查的一类 bug。

CREATE TABLE roles (
    name        TEXT PRIMARY KEY,
    permissions TEXT NOT NULL,          -- JSON 数组，如 ["site.view","site.manage"]
    created_at  INTEGER NOT NULL
);
