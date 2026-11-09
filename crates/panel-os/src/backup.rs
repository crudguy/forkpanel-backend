//! 本地备份原语。**经 `cmd.rs` 唯一子进程出口**调用 `tar`，不做 shell 拼接。

use crate::cmd::{Bin, CmdOpt};
use panel_core::{PanelError, Result};
use std::path::Path;
use std::time::Duration;

/// 把 `src_dir` 打包为 `dest`（`.tar.gz`）。`dest` 的父目录必须已存在。
///
/// ⚠ **产物权限 0600**：`tar -czf` 打开目标用的是 `O_CREAT|O_TRUNC, 0666`，
/// 新建时权限 = `0666 & ~umask`（典型 0644）；而目标**已存在**时内核忽略 mode、
/// 原权限不变。所以这里先以 0600 建一个空文件，再让 tar 覆盖它——
/// 产物从第一字节起就只有属主可读，不必「先裸写几百 MB 再 chmod」。
/// 站点归档里有用户上传与站点配置，0644 等于同机任何用户都能整站拷走。
pub async fn tar_gz(src_dir: &Path, dest: &Path) -> Result<()> {
    let parent = src_dir
        .parent()
        .ok_or_else(|| PanelError::Internal("备份源目录无父目录".into()))?;
    let name = src_dir
        .file_name()
        .ok_or_else(|| PanelError::Internal("备份源目录无名称".into()))?
        .to_string_lossy()
        .to_string();
    let dest_s = dest.to_str().ok_or_else(|| PanelError::Internal("备份目标非 UTF-8".into()))?;
    let parent_s = parent.to_str().ok_or_else(|| PanelError::Internal("备份父目录非 UTF-8".into()))?;

    // 预创建 0600（见函数注释）；随后 tar 截断写入，不改权限。
    crate::fs::create_private(dest, 0o600)?;

    let out = crate::cmd::run(
        Bin::Tar,
        &["-czf", dest_s, "-C", parent_s, name.as_str()],
        CmdOpt { timeout: Duration::from_secs(3600), ..Default::default() },
    )
    .await?;
    if out.code == Some(0) {
        // 兜一道：tar 若因实现差异重建了文件，这里把权限拉回 0600。
        crate::fs::set_mode(dest, 0o600)?;
        Ok(())
    } else {
        Err(PanelError::Command { bin: "tar".into(), detail: out.stderr })
    }
}

/// 列出归档内条目名（`tar -tzf`）——**解压前**据此做路径逃逸校验。
pub async fn list_tar_entries(archive: &Path) -> Result<Vec<String>> {
    let s = archive.to_str().ok_or_else(|| PanelError::Internal("归档路径非 UTF-8".into()))?;
    let out = crate::cmd::run(
        Bin::Tar,
        &["-tzf", s],
        CmdOpt { timeout: Duration::from_secs(60), ..Default::default() },
    )
    .await?;
    if out.code != Some(0) {
        return Err(PanelError::Command { bin: "tar".into(), detail: out.stderr });
    }
    Ok(out
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// 归档条目是否安全：**禁止绝对路径与 `..` 逃逸**。
///
/// tar 会剥离前导 `/`，但 `../` 仍可能把文件写到目标目录之外——
/// 恢复的归档虽由本面板产出，仍按不可信输入校验（纵深防御）。
pub fn is_safe_entry(name: &str) -> bool {
    if name.starts_with('/') {
        return false;
    }
    !name.split('/').any(|seg| seg == "..")
}

/// 解包 `archive` 到 `dest_parent`。
///
/// 归档内保留顶层目录名（与 `tar_gz` 对称），故解压目标是**父目录**：
/// 恢复到 `<parent>/<dirname>`，与打包时的布局一致。
pub async fn untar_gz(archive: &Path, dest_parent: &Path) -> Result<()> {
    let arch_s = archive.to_str().ok_or_else(|| PanelError::Internal("归档路径非 UTF-8".into()))?;
    let dest_s =
        dest_parent.to_str().ok_or_else(|| PanelError::Internal("解压目标非 UTF-8".into()))?;
    let out = crate::cmd::run(
        Bin::Tar,
        &["-xzf", arch_s, "-C", dest_s],
        CmdOpt { timeout: Duration::from_secs(3600), ..Default::default() },
    )
    .await?;
    if out.code == Some(0) {
        Ok(())
    } else {
        Err(PanelError::Command { bin: "tar".into(), detail: out.stderr })
    }
}

// ─────────────── 产物静态加密 ───────────────

use panel_core::crypto::MasterKey;

/// 加密容器魔数（含版本号）。解密前先校验，避免把普通 tar 当密文硬解。
pub const ENC_MAGIC: &[u8; 8] = b"PNLENC01";
/// 单块明文大小。1 MiB 是内存占用与 syscall 次数之间的折中。
const ENC_CHUNK: usize = 1024 * 1024;
/// GCM tag 长度（`nonce || ct+tag` 中的 tag 部分）
const GCM_TAG: usize = 16;

fn ioe(e: std::io::Error, what: &str) -> PanelError {
    PanelError::Io(format!("{what}: {e}"))
}

/// 读满 `buf` 或到 EOF，返回实际字节数（0 = 已在 EOF）。
///
/// **不用裸 `read`**：它允许短读，会把一个逻辑块拆成两个，
/// 于是块边界不再可推导。容器格式虽然带长度前缀（能容忍），
/// 但读满能显著减少 syscall 与容器开销。
fn read_full(r: &mut std::fs::File, buf: &mut [u8]) -> Result<usize> {
    use std::io::Read;
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ioe(e, "读取备份产物失败")),
        }
    }
    Ok(filled)
}

/// 加密备份产物（分块 AES-256-GCM）。
///
/// **为什么分块**：备份产物可能几百 MB，一次性读进内存再加密，在低配机上
/// 就是一次 OOM 事故。每块独立 nonce，块间不共享任何状态。
///
/// 容器格式（自描述，块长带前缀故不依赖固定块大小）：
/// ```text
/// magic(8B) | [ len(4B, BE) | nonce(12B) || ciphertext(+16B tag) ]*
/// ```
pub async fn encrypt_file(src: &Path, dst: &Path, key: &MasterKey) -> Result<()> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    let key = *key; // MasterKey 是 Copy
    tokio::task::spawn_blocking(move || -> Result<()> {
        // 先写临时文件再改名：中途失败不会留下"看起来完整"的半截密文
        let tmp = dst.with_extension("enc.part");
        // ⚠ 源与目标（或与临时文件）撞名 = 一边读一边写同一个文件：
        //   打开 src 之后又 truncate 同一个路径，读到的永远是"刚写进去的那几个字节"，
        //   循环不会到 EOF，产物无限增长（实测一次跑出 438MB 的 .part 才停手）。
        //   真实调用方完全可能传入这种组合（把明文临时文件放在 `<dest>.part`），
        //   所以在原语这一层直接拒绝，而不是指望每个调用方都想清楚命名。
        if src == dst || src == tmp {
            return Err(PanelError::Validation {
                field: "src",
                reason: format!(
                    "源与目标/临时文件是同一个路径（{}）：加密会边读边写同一个文件，\
                     产物无限增长。请给源与目标不同的文件名",
                    src.display()
                ),
            });
        }
        let mut r = std::fs::File::open(&src)
            .map_err(|e| ioe(e, &format!("打开 {} 失败", src.display())))?;
        // 0600：权限在 open(2) 建文件时生效，不存在「先 0644 写满再 chmod」的窗口
        let mut w = crate::fs::create_private(&tmp, 0o600)?;

        let res = encrypt_stream(&mut r, &mut w, &key).and_then(|()| {
            w.sync_all().map_err(|e| ioe(e, "落盘失败"))?;
            std::fs::rename(&tmp, &dst)
                .map_err(|e| ioe(e, &format!("重命名到 {} 失败", dst.display())))
        });
        if res.is_err() {
            // 半截密文/垃圾临时文件不能留在盘上：它和真产物只差一个后缀
            drop(w);
            let _ = std::fs::remove_file(&tmp);
        }
        res
    })
    .await
    .map_err(|e| PanelError::Internal(format!("加密任务 join 失败: {e}")))?
}

/// 把 `r` 的全部内容按分块容器格式写进 `w`。
fn encrypt_stream(
    r: &mut std::fs::File,
    w: &mut std::fs::File,
    key: &MasterKey,
) -> Result<()> {
    use std::io::Write;
    w.write_all(ENC_MAGIC).map_err(|e| ioe(e, "写入容器头失败"))?;
    let mut buf = vec![0u8; ENC_CHUNK];
    loop {
        let n = read_full(r, &mut buf)?;
        if n == 0 {
            break;
        }
        let ct = key.encrypt(&buf[..n])?;
        let len = u32::try_from(ct.len())
            .map_err(|_| PanelError::Internal("分块密文长度溢出 u32".into()))?;
        w.write_all(&len.to_be_bytes()).map_err(|e| ioe(e, "写入块长失败"))?;
        w.write_all(&ct).map_err(|e| ioe(e, "写入密文块失败"))?;
    }
    Ok(())
}

/// 解密 [`encrypt_file`] 的产物。
pub async fn decrypt_file(src: &Path, dst: &Path, key: &MasterKey) -> Result<()> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    let key = *key;
    tokio::task::spawn_blocking(move || -> Result<()> {
        use std::io::{Read, Write};
        let mut r = std::fs::File::open(&src)
            .map_err(|e| ioe(e, &format!("打开 {} 失败", src.display())))?;
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)
            .map_err(|_| PanelError::Validation {
                field: "archive",
                reason: "不是面板加密产物（容器头缺失）".into(),
            })?;
        if &magic != ENC_MAGIC {
            return Err(PanelError::Validation {
                field: "archive",
                reason: "不是面板加密产物（魔数不匹配）".into(),
            });
        }
        let tmp = dst.with_extension("dec.part");
        // ⚠ 这里写的是**明文**（解密出来的备份/库），比密文更该收紧：
        //   0600 在创建时就生效，不会出现「明文已落盘但还是 0644」的瞬间。
        let mut w = crate::fs::create_private(&tmp, 0o600)?;

        loop {
            let mut lenb = [0u8; 4];
            match r.read_exact(&mut lenb) {
                Ok(()) => {}
                // 干净地在块边界结束
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(ioe(e, "读取块长失败")),
            }
            let len = u32::from_be_bytes(lenb) as usize;
            // 长度合法性先于分配：否则一个损坏的长度字段就能让面板申请巨量内存
            if !(12 + GCM_TAG..=ENC_CHUNK + 12 + GCM_TAG).contains(&len) {
                return Err(PanelError::Validation {
                    field: "archive",
                    reason: format!("容器块长非法（{len}），文件可能已损坏"),
                });
            }
            let mut ct = vec![0u8; len];
            r.read_exact(&mut ct).map_err(|e| ioe(e, "密文块不完整"))?;
            let pt = key.decrypt(&ct)?;
            w.write_all(&pt).map_err(|e| ioe(e, "写入明文失败"))?;
        }
        w.sync_all().map_err(|e| ioe(e, "落盘失败"))?;
        drop(w);
        std::fs::rename(&tmp, &dst)
            .map_err(|e| ioe(e, &format!("重命名到 {} 失败", dst.display())))?;
        Ok(())
    })
    .await
    .map_err(|e| PanelError::Internal(format!("解密任务 join 失败: {e}")))?
}

/// 文件是否为面板加密容器（只读前 8 字节，不加载整个文件）。
pub fn is_encrypted_file(p: &Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(p) else { return false };
    let mut magic = [0u8; 8];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    &magic == ENC_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> MasterKey {
        MasterKey::from_bytes(&[7u8; 32]).expect("32 字节密钥")
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip_including_multiblock() {
        let dir = std::env::temp_dir().join(format!("panel-enc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("plain.bin");
        // 2.5 MiB > ENC_CHUNK(1 MiB)：确保多块路径真的被走到
        let data: Vec<u8> = (0..(ENC_CHUNK * 5 / 2)).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let enc = dir.join("plain.enc");
        let back = dir.join("back.bin");
        encrypt_file(&src, &enc, &test_key()).await.unwrap();
        assert!(is_encrypted_file(&enc), "加密产物应被识别为容器");
        assert!(!is_encrypted_file(&src), "明文不应被认作容器");
        decrypt_file(&enc, &back, &test_key()).await.unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), data, "往返后必须逐字节一致");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wrong_key_and_non_container_are_rejected() {
        let dir = std::env::temp_dir().join(format!("panel-enc-neg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("a.txt");
        std::fs::write(&src, b"hello").unwrap();
        let enc = dir.join("a.enc");
        encrypt_file(&src, &enc, &test_key()).await.unwrap();

        // 错误密钥必须失败（GCM 完整性校验）——绝不能静默产出垃圾明文
        let other = MasterKey::from_bytes(&[9u8; 32]).unwrap();
        let out = dir.join("out.bin");
        assert!(decrypt_file(&enc, &out, &other).await.is_err(), "错误密钥必须解密失败");

        // 非容器：给出明确错误，而不是崩或产出垃圾
        let bad = dir.join("bad.enc");
        std::fs::write(&bad, b"not an encrypted container at all").unwrap();
        assert!(decrypt_file(&bad, &out, &test_key()).await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn missing_parent_is_rejected() {
        // `/` 无父目录 → 构造期即拒绝，不 spawn
        let r = tar_gz(Path::new("/"), Path::new("/tmp/x.tar.gz")).await;
        assert!(r.is_err());
    }

    #[test]
    fn entry_safety_rejects_escape_and_absolute_paths() {
        assert!(is_safe_entry("site/index.html"));
        assert!(is_safe_entry("site/"));
        // 逃逸：任一路径段为 .. 即拒绝
        assert!(!is_safe_entry("../etc/passwd"));
        assert!(!is_safe_entry("site/../../etc/passwd"));
        assert!(!is_safe_entry("site/../shadow"));
        // 绝对路径
        assert!(!is_safe_entry("/etc/passwd"));
    }
}
