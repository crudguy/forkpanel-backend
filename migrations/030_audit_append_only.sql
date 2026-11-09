-- 030：审计日志强制 append-only（production-readiness §3.5 P1）。
--
-- 边界诚实化（与 migrate.rs 的「别夸大成防篡改」同口径）：触发器挡的是
-- **代码路径误改/越权删改**——任何 handler、未来新功能、清理任务之外的
-- UPDATE/DELETE 都当场报错而不是静默成功。能写库文件的 root 进程仍可
-- DROP TRIGGER，那属于主机层沦陷；篡改留痕由 doctor 的 audit_append_only
-- 检查（触发器必须在位）提供。
--
-- DELETE 的合法唯一通道是保留期修剪：cleanup::prune_audit 先向单行令牌表
-- _audit_permit INSERT（RAII 回收）。
-- ⚠ 为什么令牌是 main 库的真表而不是 temp 表：SQLite 规定**挂在 main 表上的
--   触发器不得引用 temp 库对象**（CREATE 即报 "trigger ... cannot reference
--   objects in database temp"，已实测踩中）。真表令牌反而是更强的语义——
--   prune_audit 在 writer.exec 的事务里执行，令牌的 INSERT 与回收 DELETE
--   同事务提交，**任何已提交状态都不存在游离令牌**；崩溃即整体回滚。
-- ⚠ 触发器因此也挡住「直接 DELETE FROM _audit_permit 外的表」以外的任何
--   绕过：想裸删 audit_log 必须先有令牌行，而令牌行只在 prune 事务内存在。

CREATE TABLE _audit_permit(permit INTEGER PRIMARY KEY);

CREATE TRIGGER audit_append_only_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE forbidden');
END;

CREATE TRIGGER audit_append_only_no_delete
BEFORE DELETE ON audit_log
WHEN NOT EXISTS (SELECT 1 FROM _audit_permit)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE requires prune permit (cleanup::prune_audit)');
END;
