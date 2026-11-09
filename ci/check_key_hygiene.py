#!/usr/bin/env python3
"""主密钥 / 备份加密的接线守卫（报告 §3.4 P1 / §4.2 G12）。

背景：报告 §3.4 有三条 P1 直接指向同一件事——**钥匙与备份的保护是散着做的**：
  - `master.key` 只在不存在时生成，之后永远只读，全仓没有任何 rekey 方案；
  - 备份产物默认不加密，且没有显式权限（依赖 umask，典型 0644）；
  - 「丢密钥」只有一句文档提醒，没有演练、没有可执行的校验手段。

本守卫钉住**接线**，行为由 `ci/e2e-key-drill.sh` 真跑覆盖：
  [1] `encrypt` 默认开启，且后端 / openapi×2 / 前端四处**一致**（漂一处就有一处被骗）
  [2] `INSERT INTO backup_jobs` 必须显式列出 `encrypt`（否则 schema 的 DEFAULT 0 生效）
  [3] 产物写入一律 0600（tar / 加密 / 解密 / VACUUM INTO 四个原语逐个查）
  [4] rekey 的声明表与 `migrations/*.sql` 里真实存在的 `*_enc` 列**集合相等**
  [5] settings 里 `enc:<hex>` 的键与 rekey 声明一致
  [6] 恢复/校验/导出路径**不得**用会自动生成密钥的 `load_master_key`

为什么 [6] 单列一条：`load_master_key` 在文件缺失时顺手 `ensure_master_key`。
恢复路径用它，就会把「密钥丢了」变成「密钥不对」——报 `aes-gcm decrypt` 失败，
用户以为是产物损坏；更糟的是**明文产物**会恢复成功，而库里所有密文永久打不开。
这是实测踩出来的（先在本文件里判红，才有 e2e 那条断言）。

恒绿纪律：
  - 判据一律剔注释后再匹配（这些文件里满篇注释都在**讨论** encrypt/0600/rekey，
    不剔的话注释就能冒充实现）；
  - 提取为空 ⇒ 直接判红，不算通过；
  - 覆盖率判据用**集合相等**而不是「包含」：新增一个密文列而不更新 rekey 表，
    必须变红 ——「包含」只会在删列时发现。

用法：python3 ci/check_key_hygiene.py [仓库根目录]
"""
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
fail = 0


def ok(msg):
    print(f"  ✓ {msg}")


def bad(msg):
    global fail
    print(f"  ✗ {msg}")
    fail = 1


def strip_rust_comments(src: str) -> str:
    """剔掉 `//` 行注释与 `/* */` 块注释（保留字符串里的内容不动，本项目够用）。"""
    out = []
    for line in src.splitlines():
        # 行首整行注释直接丢；行尾注释按「不在字符串里」粗略截断
        stripped = re.sub(r"\s*//.*$", "", line)
        out.append(stripped)
    src = "\n".join(out)
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)


def strip_cfg_test_blocks(src: str) -> str:
    """把 `#[cfg(test)]` 修饰的模块/函数**按大括号配对整体剥掉**（含其内部全部内容）。

    ⚠ 不能用 `src.rfind("#[cfg(test)]")` 一刀切：一个文件里有多个测试模块时，
    最后一个之前的所有测试代码都会留在"生产段"里（实测 `backups.rs` 的测试夹具
    INSERT 就漏了下来，于是 [2] 看着在跑、实际匹配到的是夹具）。这类"切不干净"
    不会报错，只会让判据慢慢退化成恒绿。
    """
    while True:
        m = re.search(r"#\[cfg\(test\)\]", src)
        if not m:
            return src
        brace = src.find("{", m.end())
        semi = src.find(";", m.end())
        if semi != -1 and (brace == -1 or semi < brace):
            # 形如 `#[cfg(test)] use …;` —— 整句删掉
            src = src[: m.start()] + src[semi + 1 :]
            continue
        if brace == -1:
            return src[: m.start()]
        depth = 0
        for j in range(brace, len(src)):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    src = src[: m.start()] + src[j + 1 :]
                    break
        else:
            return src[: m.start()]  # 括号不配对：保守截断


def production(rel: str) -> str:
    """读生产段：剥 `#[cfg(test)]` 块 + 剔注释。"""
    p = ROOT / rel
    if not p.is_file() or p.stat().st_size == 0:
        bad(f"{rel} 不存在或为空——提取前提不成立，绝不能当作通过")
        return ""
    src = p.read_text(encoding="utf-8", errors="replace")
    src = strip_cfg_test_blocks(src)
    src = strip_rust_comments(src)
    if not src.strip():
        bad(f"{rel} 剔注释/剥测试后为空——判据会恒绿")
    return src


BE_BACKUP = "crates/panel-api/src/routes/backups.rs"
OS_BACKUP = "crates/panel-os/src/backup.rs"
DB_LIB = "crates/panel-db/src/lib.rs"
REKEY = "crates/panel-db/src/rekey.rs"
CLI_DB = "crates/panel-cli/src/cmd/db.rs"
CLI_KEY = "crates/panel-cli/src/cmd/key.rs"
SETTINGS = "crates/panel-api/src/routes/settings.rs"
OPENAPI_BE = "docs/api/openapi.yaml"
OPENAPI_FE = "../forkpanel-frontend/src/api/openapi.yaml"
FE_BACKUPS = "../forkpanel-frontend/src/views/BackupsView.vue"

print("== [1] encrypt 默认开启，四处一致 ==")
be = production(BE_BACKUP)
m = re.search(r"req\.encrypt\s*\.unwrap_or\((\w+)\)\s*as\s*i32", be)
if not m:
    bad(f"{BE_BACKUP} 里找不到 create 路径的 encrypt 缺省值（结构变了？判据会空转）")
elif m.group(1) == "true":
    ok("后端 create：省略 encrypt ⇒ true")
else:
    bad(f"后端 create 的 encrypt 缺省是 {m.group(1)}，应为 true（备份默认不加密）")

for rel in (OPENAPI_BE, OPENAPI_FE):
    p = ROOT / rel
    if not p.is_file():
        bad(f"{rel} 不存在")
        continue
    text = p.read_text(encoding="utf-8", errors="replace")
    # 只看 schema / 请求体里的 encrypt 定义，不看描述文字
    hits = re.findall(r"^\s*encrypt:\s*\{[^}]*\}", text, re.M)
    defaults = [h for h in hits if "default:" in h]
    wrong = [h for h in defaults if "default: true" not in h]
    if not defaults:
        bad(f"{rel} 里没有带 default 的 encrypt 定义（判据会空转）")
    elif wrong:
        bad(f"{rel} 有 {len(wrong)} 处 encrypt default 不是 true：{wrong[0].strip()[:80]}")
    else:
        ok(f"{rel}：{len(defaults)} 处 encrypt default 均为 true")

fe = production(FE_BACKUPS) if (ROOT / FE_BACKUPS).is_file() else ""
if not fe:
    bad(f"{FE_BACKUPS} 读不到——前端默认值无法核对")
else:
    # 表单初值与"重置表单"两处都必须是 true，任何一处留 false 都会让用户新建出明文计划
    vals = re.findall(r"encrypt:\s*(true|false)", fe)
    if not vals:
        bad(f"{FE_BACKUPS} 里找不到 encrypt 初值（判据会空转）")
    elif all(v == "true" for v in vals):
        ok(f"{FE_BACKUPS}：{len(vals)} 处 encrypt 初值均为 true")
    else:
        bad(f"{FE_BACKUPS} 仍有 encrypt: false 的初值（共 {len(vals)} 处：{vals}）")

print("== [2] INSERT INTO backup_jobs 必须显式列出 encrypt ==")
# 只认**生产**那条创建路径：它的列清单里有 `cron_expr`（用户可填的计划字段），
# 测试夹具只插 id/kind/…。按内容认而不是按"第一条/最后一条"，顺序变了也不会误判。
inserts = [re.sub(r"\s+", "", s) for s in re.findall(r"INSERT INTO backup_jobs\(([^)]*)\)", be, re.S)]
prod_inserts = [s for s in inserts if "cron_expr" in s]
if not prod_inserts:
    bad("找不到生产创建路径的 INSERT INTO backup_jobs（判据会空转）")
elif len(prod_inserts) > 1:
    bad(f"生产创建路径出现 {len(prod_inserts)} 处 INSERT，判据可能只覆盖其中之一")
elif "encrypt" not in prod_inserts[0]:
    bad("生产 INSERT 未列 encrypt：schema 的 DEFAULT 0 会让新计划静默不加密")
else:
    ok(f"生产 INSERT 显式列出 encrypt（共 {len(inserts)} 处 INSERT，其余为测试夹具）")

print("== [3] 产物写入一律 0600 ==")


def fn_body(src: str, name: str) -> str:
    """取函数体（按大括号配对），取不到返回空串。"""
    m = re.search(rf"fn\s+{name}\s*(?:<[^>]*>)?\s*\(", src)
    if not m:
        return ""
    i = src.find("{", m.end())
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    return ""


osrc = production(OS_BACKUP)
for fname, why in (
    ("tar_gz", "站点/库归档"),
    ("encrypt_file", "加密产物"),
    ("decrypt_file", "解密出的明文"),
):
    body = fn_body(osrc, fname)
    if not body:
        bad(f"{OS_BACKUP} 里找不到 {fname}（判据会空转）")
    elif "0o600" in body:
        ok(f"{fname}（{why}）写文件时用 0o600")
    else:
        bad(f"{fname}（{why}）没有 0600 —— 产物会按 umask 给到 0644")

dbsrc = production(DB_LIB)
body = fn_body(dbsrc, "backup_to")
if not body:
    bad(f"{DB_LIB} 里找不到 backup_to（判据会空转）")
elif "0o600" in body:
    ok("backup_to（VACUUM INTO 产物）建完即收紧到 0600")
else:
    bad("backup_to 没有设 0600 —— 面板库会以 0644 落盘（含口令密文与审计明细）")

print("== [4] rekey 声明表 == schema 里真实存在的 *_enc 列 ==")
declared = set()
rsrc = production(REKEY)
for tbl, col in re.findall(r'\(\s*"(\w+)"\s*,\s*"(\w+)"\s*,', rsrc):
    if col.endswith("_enc"):
        declared.add((tbl, col))
if not declared:
    bad(f"{REKEY} 里解析不出 BLOB_COLUMNS（判据会空转）")

in_schema = set()
for sql in sorted((ROOT / "migrations").glob("*.sql")):
    text = sql.read_text(encoding="utf-8", errors="replace")
    text = re.sub(r"--.*$", "", text, flags=re.M)  # SQL 注释
    table = None
    for line in text.splitlines():
        mt = re.search(r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)", line, re.I)
        if mt:
            table = mt.group(1)
        ma = re.search(r"ALTER TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+_enc)\b", line, re.I)
        if ma:
            in_schema.add((ma.group(1), ma.group(2)))
            continue
        mc = re.search(r"^\s*(\w+_enc)\s+BLOB", line, re.I)
        if mc and table:
            in_schema.add((table, mc.group(1)))
        if re.match(r"^\s*\)\s*;", line):
            table = None

if not in_schema:
    bad("migrations 里解析不出任何 *_enc 列（判据会空转）")
elif declared == in_schema:
    ok(f"声明表与 schema 完全一致（{len(declared)} 列：{'、'.join(sorted(c for _, c in declared))}）")
else:
    miss = in_schema - declared
    extra = declared - in_schema
    if miss:
        bad(f"schema 里有密文列未被 rekey 覆盖：{sorted(miss)} —— 换钥后它们永久解不开")
    if extra:
        bad(f"rekey 声明了 schema 里不存在的列：{sorted(extra)}（改名后漏改？）")

print("== [5] settings 里的 enc:<hex> 与 rekey 声明一致 ==")
m_keys = re.search(r"SETTINGS_ENC_KEYS[^=]*=\s*&\[([^\]]*)\]", rsrc)
declared_keys = set(re.findall(r'"([\w.]+)"', m_keys.group(1))) if m_keys else set()
s_set = production(SETTINGS)
used = set(re.findall(r'K_LLM_API_KEY:\s*&str\s*=\s*"([\w.]+)"', s_set))
if not declared_keys:
    bad(f"{REKEY} 里解析不出 SETTINGS_ENC_KEYS（判据会空转）")
elif not used:
    bad(f"{SETTINGS} 里找不到 K_LLM_API_KEY 的定义（判据会空转）")
elif declared_keys == used:
    ok(f"settings 密文键一致：{sorted(declared_keys)}")
else:
    bad(f"settings 密文键不一致：rekey={sorted(declared_keys)} 实际写入={sorted(used)}")
if "enc:" in s_set:
    ok("settings 写入方仍用 enc: 前缀（与 rekey 的解析一致）")
else:
    bad("settings 写入方不再是 enc: 前缀 —— rekey 会把它当明文跳过")

print("== [6] 恢复/校验/导出路径不得自动生成主密钥 ==")
for rel, allowed in ((CLI_DB, "load_existing_master_key"), (CLI_KEY, "load_existing_master_key")):
    src = production(rel)
    if not src:
        continue
    # `load_master_key` 是「缺失就生成」的版本；恢复路径用它会掩盖丢密钥
    hits = re.findall(r"\bload_master_key\s*\(", src)
    if hits:
        bad(f"{rel} 仍调用 load_master_key（缺失时会静默生成新钥，丢密钥被伪装成产物损坏）")
    else:
        ok(f"{rel} 只用 {allowed}（缺失时显式失败）")

print("== [7] 演练脚本挂在 make guards / e2e 聚合器上 ==")
mk = (ROOT / "Makefile").read_text(encoding="utf-8", errors="replace")
m_guards = re.search(r"^guards:\n((?:\t.*\n|\n)*)", mk, re.M)
if not m_guards:
    bad("Makefile 找不到 guards 目标")
else:
    body = m_guards.group(1)
    for need in ("check_key_hygiene.py",):
        if need in body:
            ok(f"guards 里调用了 ci/{need}")
        else:
            bad(f"guards 未调用 ci/{need} —— 守卫写好也不会跑")

# 演练脚本不能是孤儿：写好了没人调用 = 「存在但不跑」（G10 踩过的坑）。
# 它要自建实例并停服，故不进 `make check`，但必须同时有 make 入口与聚合器条目。
if re.search(r"^e2e-key-drill:\n\tbash ci/e2e-key-drill\.sh", mk, re.M):
    ok("Makefile 有 e2e-key-drill 目标")
else:
    bad("Makefile 没有 e2e-key-drill 目标 —— 演练脚本会变成孤儿")
agg = (ROOT / "ci" / "e2e-all.sh").read_text(encoding="utf-8", errors="replace")
m_scripts = re.search(r"SCRIPTS=\(([^)]*)\)", agg, re.S)
if not m_scripts:
    bad("e2e-all.sh 提取不到 SCRIPTS（判据会空转）")
elif "e2e-key-drill" in m_scripts.group(1).split():
    ok("e2e-all.sh 的 SCRIPTS 含 e2e-key-drill（CI E2E job 会真跑）")
else:
    bad("e2e-all.sh 的 SCRIPTS 没有 e2e-key-drill —— CI 里永远不跑")

if fail:
    print("✗ check_key_hygiene：主密钥 / 备份加密的接线未通过")
    sys.exit(1)
print("PASS：encrypt 默认开启且四处一致、产物 0600、rekey 覆盖面完整、恢复路径不静默生成密钥")
