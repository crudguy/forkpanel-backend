//! 备份远端存储（WebDAV / S3 兼容）。
//!
//! ## 为什么走 curl 而不是 HTTP 客户端 crate
//! 1. 依赖预算只剩 1 位（见 `ci/check-layering.sh` 的 [8]）；
//! 2. curl 自带 `--aws-sigv4`，S3 签名不必自己实现——手写 SigV4 属典型的
//!    高风险重复劳动（签名算错只会得到 403，排查成本极高）；
//! 3. 与 Webhook 投递共用同一套出口纪律：argv 直传、不经 shell、固定超时、`--fail`。
//!
//! ## 纪律
//! 1. URL 经与 webhook 同一份实现校验（仅 http/https、拦控制字符）；
//! 2. 凭据（`--user "ak:sk"`）作为**单个 argv** 传入，不拼进 shell 字符串；
//! 3. 固定 `--max-time`：备份产物可能很大，但"无限挂起"比"传失败"更糟——
//!    挂住的任务会一直占着调度槽；
//! 4. 失败只返回 Err，**由调用方决定是否影响"本次备份成功"的判定**
//!    （当前策略：不影响——本地备份已经成功，远端失败只落通知）。

use panel_core::PanelError;
use panel_os::{Bin, CmdOpt};
use std::path::Path;
use std::time::Duration;

/// 上传超时：产物可能几百 MB，给足时间；但不能不设上限。
const UPLOAD_TIMEOUT_SECS: u64 = 3600;
/// 单次删除的超时（删除是幂等轻量操作，不该占着连接）
const DELETE_TIMEOUT_SECS: u64 = 120;
/// 列表 / 下载的超时。列表是元数据操作应很快；下载按产物大小给足。
const LIST_TIMEOUT_SECS: u64 = 120;
/// 列表翻页上限。S3 每页最多 1000 个 ⇒ 上限约 5 万个对象，远超任何备份目录的
/// 合理规模；设上限是为了**不会**因为服务端反复返回同一个令牌而无限循环。
const LIST_MAX_PAGES: usize = 50;
const DOWNLOAD_TIMEOUT_SECS: u64 = 3600;
/// 连接自检用的探针对象名。固定名且用完即删，不会在远端累积垃圾。
pub const PROBE_OBJECT: &str = ".panel-conn-test";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteKind {
    Webdav,
    S3,
}

impl RemoteKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "webdav" => Some(Self::Webdav),
            "s3" => Some(Self::S3),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webdav => "webdav",
            Self::S3 => "s3",
        }
    }
}

/// 远端目标。
///
/// `secret` 是**已解密**的凭据——本模块不做解密：解密需要主密钥，而主密钥只存在于
/// `AppState`，让本模块去够主密钥会把密钥的暴露面扩大一圈。
#[derive(Debug, Clone)]
pub struct RemoteTarget {
    pub kind: RemoteKind,
    pub url: String,
    pub bucket: Option<String>,
    pub prefix: Option<String>,
    pub region: Option<String>,
    pub user: Option<String>,
    pub secret: Option<String>,
}

/// 复用 webhook 的 URL 纪律（仅 http/https、拦控制字符），只把报错字段名换成
/// 远端配置的——**纪律共用同一份实现**，否则"两套 URL 校验，漏的那套就是被绕过的"。
fn validate_remote_url(u: &str) -> Result<(), PanelError> {
    crate::webhook::validate_url(u).map_err(|e| match e {
        PanelError::Validation { reason, .. } => PanelError::Validation {
            field: "remote_url".into(),
            reason,
        },
        other => other,
    })
}

impl RemoteTarget {
    /// 远端对象 URL（上传/删除的目标）。
    fn object_url(&self, name: &str) -> Result<String, PanelError> {
        match self.kind {
            RemoteKind::Webdav => {
                let base = self.url.trim_end_matches('/');
                Ok(format!("{base}/{name}"))
            }
            RemoteKind::S3 => {
                let bucket = self.bucket.as_deref().filter(|b| !b.is_empty()).ok_or_else(|| {
                    PanelError::Validation {
                        field: "remote_bucket".into(),
                        reason: "S3 需要填写 bucket".into(),
                    }
                })?;
                let base = self.url.trim_end_matches('/');
                let key = match self.prefix.as_deref().map(|p| p.trim_matches('/')) {
                    Some(p) if !p.is_empty() => format!("{p}/{name}"),
                    _ => name.to_string(),
                };
                Ok(format!("{base}/{bucket}/{key}"))
            }
        }
    }

    /// 配置自检：构造一次**真实**对象 URL 并走 URL 纪律校验。
    ///
    /// 为什么不是"只校验基地址"：拼接本身会引入问题（S3 的 bucket/prefix 组合、
    /// 双斜杠），只校验基地址会漏掉它们——而执行路径校验的是**拼好的** URL，
    /// 两处不一致就等于"保存得进去、跑起来才失败"。
    pub fn validate(&self) -> Result<(), PanelError> {
        let u = self.object_url(PROBE_OBJECT)?;
        validate_remote_url(&u)
    }

    /// 凭据相关的 argv（两种协议都用 `--user`，S3 另需 `--aws-sigv4`）。
    fn auth_args(&self) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        if self.kind == RemoteKind::S3 {
            let region = self
                .region
                .clone()
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| "us-east-1".into());
            a.push("--aws-sigv4".into());
            a.push(format!("aws:amz:{region}:s3"));
        }
        if let (Some(u), Some(s)) = (&self.user, &self.secret) {
            if !u.is_empty() {
                // 整个 "user:secret" 作为单个 argv，不经 shell、无拼接注入面
                a.push("--user".into());
                a.push(format!("{u}:{s}"));
            }
        }
        a
    }

    async fn run_curl(&self, args: Vec<String>, timeout_secs: u64) -> Result<(), PanelError> {
        if !Bin::Curl.available() {
            // 宿主无 curl：诚实失败，不假装传成功
            return Err(PanelError::Unsupported("curl"));
        }
        // args 必须活到调用结束——arg_refs 借用它
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = panel_os::run(
            Bin::Curl,
            &arg_refs,
            CmdOpt {
                // 给 curl 留出"自己超时后写错误信息"的余量
                timeout: Duration::from_secs(timeout_secs + 30),
                ..Default::default()
            },
        )
        .await?;
        if out.code != Some(0) {
            return Err(PanelError::Command {
                bin: "curl".into(),
                detail: out.stderr.trim().to_string(),
            });
        }
        Ok(())
    }

    /// 需要读响应体的调用（LIST）：与 [`Self::run_curl`] 同纪律，但返回 stdout。
    async fn curl_stdout(&self, args: Vec<String>, timeout_secs: u64) -> Result<String, PanelError> {
        if !Bin::Curl.available() {
            return Err(PanelError::Unsupported("curl"));
        }
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let out = panel_os::run(
            Bin::Curl,
            &arg_refs,
            CmdOpt { timeout: Duration::from_secs(timeout_secs + 30), ..Default::default() },
        )
        .await?;
        if out.code != Some(0) {
            return Err(PanelError::Command {
                bin: "curl".into(),
                detail: out.stderr.trim().to_string(),
            });
        }
        Ok(out.stdout)
    }

    /// 从 S3 列表响应里取"下一页"令牌；未截断或没有令牌 → `None`。
    ///
    /// S3 `list-type=2` **单次最多 1000 个对象**，超过会回 `IsTruncated=true` +
    /// `NextContinuationToken`。不翻页的话远端看起来"只有 1000 个产物"，
    /// 用户会以为更早的备份丢了——这是典型的静默截断。
    ///
    /// WebDAV 的 PROPFIND 没有分页概念，永远返回 `None`。
    fn next_continuation(&self, body: &str) -> Option<String> {
        if self.kind != RemoteKind::S3 {
            return None;
        }
        let truncated = extract_tag_values(body, "IsTruncated");
        if !truncated.iter().any(|t| t.trim() == "true") {
            return None;
        }
        extract_tag_values(body, "NextContinuationToken")
            .into_iter()
            .find(|t| !t.trim().is_empty())
            .map(|t| t.trim().to_string())
    }

    /// 列表用的 URL 与请求方式（两种协议完全不同，抽出来便于单测）。
    ///
    /// `continuation` 仅 S3 用：翻页时带上 `continuation-token`。
    fn list_request(
        &self,
        prefix: &str,
        continuation: Option<&str>,
    ) -> Result<(String, Vec<String>), PanelError> {
        let base = self.url.trim_end_matches('/');
        match self.kind {
            RemoteKind::Webdav => {
                let url = format!("{base}/");
                validate_remote_url(&url)?;
                let body = r#"<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>"#;
                Ok((
                    url,
                    vec![
                        "--request".into(), "PROPFIND".into(),
                        "--header".into(), "Depth: 1".into(),
                        "--header".into(), "Content-Type: application/xml".into(),
                        "--data".into(), body.into(),
                    ],
                ))
            }
            RemoteKind::S3 => {
                let bucket = self.bucket.as_deref().filter(|b| !b.is_empty()).ok_or_else(|| {
                    PanelError::Validation {
                        field: "remote_bucket".into(),
                        reason: "S3 需要填写 bucket".into(),
                    }
                })?;
                let key_prefix = match self.prefix.as_deref().map(|p| p.trim_matches('/')) {
                    Some(p) if !p.is_empty() => format!("{p}/{prefix}"),
                    _ => prefix.to_string(),
                };
                let mut url = format!(
                    "{base}/{bucket}?list-type=2&prefix={}",
                    urlencode(&key_prefix)
                );
                if let Some(t) = continuation.map(str::trim).filter(|t| !t.is_empty()) {
                    url.push_str("&continuation-token=");
                    url.push_str(&urlencode(t));
                }
                validate_remote_url(&url)?;
                Ok((url, Vec::new()))
            }
        }
    }

    /// 列出远端以 `prefix` 开头的对象名（**只返回最后一段文件名**）。
    ///
    /// 为什么只需要名字：恢复要按名字取回对象，UI 也只展示名字。大小/时间在
    /// S3 要额外 HEAD、在 WebDAV 要解析 getcontentlength——先不做，避免为
    /// 展示信息引入更多协议分支（真需要时再加）。
    ///
    /// S3 会**自动翻页**直到取完（每页最多 1000 个，见 [`Self::next_continuation`]）；
    /// 页数超过 [`LIST_MAX_PAGES`] 时停止并如实告警——不留一个"看着完整其实截断"的
    /// 列表。
    pub async fn list(&self, prefix: &str) -> Result<Vec<String>, PanelError> {
        let mut names: Vec<String> = Vec::new();
        let mut token: Option<String> = None;

        for _ in 0..LIST_MAX_PAGES {
            let (url, extra) = self.list_request(prefix, token.as_deref())?;
            let mut args: Vec<String> = vec![
                "--fail".into(),
                "--silent".into(),
                "--show-error".into(),
                "--max-time".into(),
                LIST_TIMEOUT_SECS.to_string(),
            ];
            args.extend(extra);
            args.extend(self.auth_args());
            args.push(url);
            let body = self.curl_stdout(args, LIST_TIMEOUT_SECS).await?;

            let mut page: Vec<String> = match self.kind {
                RemoteKind::Webdav => {
                    let mut raw = extract_tag_values(&body, "D:href");
                    raw.extend(extract_tag_values(&body, "d:href"));
                    raw.extend(extract_tag_values(&body, "href"));
                    raw.iter().map(|h| last_segment(h)).collect()
                }
                RemoteKind::S3 => extract_tag_values(&body, "Key")
                    .iter()
                    .map(|k| last_segment(k))
                    .collect(),
            };
            page.retain(|n| !n.is_empty() && n.starts_with(prefix));
            names.extend(page);

            token = self.next_continuation(&body);
            if token.is_none() {
                break;
            }
        }
        if token.is_some() {
            eprintln!(
                "[panel] 远端对象超过 {} 页（约 {} 个），列表到此为止——\
                 如需完整清单请缩小 prefix 或分批清理",
                LIST_MAX_PAGES,
                LIST_MAX_PAGES * 1000
            );
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// 把远端对象下载到本地 `dest`（覆盖写）。
    pub async fn download(&self, name: &str, dest: &Path) -> Result<(), PanelError> {
        let url = self.object_url(name)?;
        validate_remote_url(&url)?;
        let dest_s = dest
            .to_str()
            .ok_or_else(|| PanelError::Internal("下载目标路径非 UTF-8".into()))?;
        let mut args: Vec<String> = vec![
            "--fail".into(),
            "--silent".into(),
            "--show-error".into(),
            "--max-time".into(),
            DOWNLOAD_TIMEOUT_SECS.to_string(),
            "--output".into(),
            dest_s.to_string(),
        ];
        args.extend(self.auth_args());
        args.push(url);
        self.run_curl(args, DOWNLOAD_TIMEOUT_SECS).await
    }

    /// 上传本地文件到远端。返回远端地址（展示 / 日志用）。
    pub async fn upload(&self, local: &Path, name: &str) -> Result<String, PanelError> {
        let url = self.object_url(name)?;
        validate_remote_url(&url)?;
        let local_s = local
            .to_str()
            .ok_or_else(|| PanelError::Internal("备份产物路径非 UTF-8".into()))?;

        let mut args: Vec<String> = vec![
            "--fail".into(),
            "--silent".into(),
            "--show-error".into(),
            "--max-time".into(),
            UPLOAD_TIMEOUT_SECS.to_string(),
            "--upload-file".into(),
            local_s.to_string(),
        ];
        args.extend(self.auth_args());
        args.push(url.clone());
        self.run_curl(args, UPLOAD_TIMEOUT_SECS).await?;
        Ok(url)
    }

    /// 删除远端对象。
    ///
    /// 调用方是"本地裁剪旧产物"——因此**删除失败不该让备份任务失败**：
    /// 本地已经留好了，远端多一个旧对象不是事故（只是不够干净）。
    pub async fn delete(&self, name: &str) -> Result<(), PanelError> {
        let url = self.object_url(name)?;
        validate_remote_url(&url)?;
        let mut args: Vec<String> = vec![
            "--fail".into(),
            "--silent".into(),
            "--show-error".into(),
            "--max-time".into(),
            DELETE_TIMEOUT_SECS.to_string(),
            "--request".into(),
            "DELETE".into(),
        ];
        args.extend(self.auth_args());
        args.push(url);
        self.run_curl(args, DELETE_TIMEOUT_SECS).await
    }

    /// 连接自检：上传一个探针对象，再删除它。返回探针对象 URL。
    ///
    /// 为什么用 PUT 而不是 HEAD/LIST：WebDAV 与 S3 的"只读探测"是两套协议
    /// （PROPFIND / HeadBucket），得写两遍；而**备份真正需要的能力就是 PUT**——
    /// 用实际要用的操作探测，才不算撒谎（存在 HEAD 通过、PUT 被拒的存储）。
    pub async fn probe(&self) -> Result<String, PanelError> {
        let url = self.object_url(PROBE_OBJECT)?;
        validate_remote_url(&url)?;
        let tmp = std::env::temp_dir().join(format!("panel-probe-{}", std::process::id()));
        std::fs::write(&tmp, b"panel-connection-probe")
            .map_err(|e| PanelError::Io(e.to_string()))?;
        let up = self.upload(&tmp, PROBE_OBJECT).await;
        let _ = std::fs::remove_file(&tmp);
        up?;
        // 探针清理失败**不改变连接结论**（能力本身已验证），记一笔即可
        if let Err(e) = self.delete(PROBE_OBJECT).await {
            eprintln!("[panel] 远端探针对象清理失败（连接结论仍然有效）: {e}");
        }
        Ok(url)
    }

    /// 远端能力是否可用（curl 是否在位）。前端据此置灰远端配置项。
    pub fn available() -> bool {
        Bin::Curl.available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webdav() -> RemoteTarget {
        RemoteTarget {
            kind: RemoteKind::Webdav,
            url: "https://dav.example.com/backups/".into(),
            bucket: None,
            prefix: None,
            region: None,
            user: Some("u".into()),
            secret: Some("p".into()),
        }
    }

    fn s3() -> RemoteTarget {
        RemoteTarget {
            kind: RemoteKind::S3,
            url: "https://s3.example.com".into(),
            bucket: Some("my-bucket".into()),
            prefix: Some("/panel/prod/".into()),
            region: Some("cn-north-1".into()),
            user: Some("AK".into()),
            secret: Some("SK".into()),
        }
    }

    #[test]
    fn webdav_object_url_joins_without_double_slash() {
        assert_eq!(
            webdav().object_url("plan1-1700000000.tar.gz").unwrap(),
            "https://dav.example.com/backups/plan1-1700000000.tar.gz"
        );
    }

    #[test]
    fn s3_object_url_includes_bucket_and_trimmed_prefix() {
        // 前缀两端的斜杠必须被吃掉，否则会生成 `//panel/prod//file` 这种 key
        assert_eq!(
            s3().object_url("x.tar.gz").unwrap(),
            "https://s3.example.com/my-bucket/panel/prod/x.tar.gz"
        );
        // 无前缀时退化成 bucket 根
        let mut t = s3();
        t.prefix = None;
        assert_eq!(t.object_url("x.tar.gz").unwrap(), "https://s3.example.com/my-bucket/x.tar.gz");
    }

    #[test]
    fn s3_requires_bucket() {
        let mut t = s3();
        t.bucket = None;
        assert!(t.object_url("x").is_err(), "缺 bucket 必须报错，而不是拼出非法 URL");
    }

    #[test]
    fn auth_args_shape() {
        // webdav：只有 --user
        let a = webdav().auth_args();
        assert_eq!(a, vec!["--user".to_string(), "u:p".to_string()]);
        // s3：先 --aws-sigv4（带 region），再 --user
        let b = s3().auth_args();
        assert_eq!(b[0], "--aws-sigv4");
        assert_eq!(b[1], "aws:amz:cn-north-1:s3");
        assert_eq!(b[2], "--user");
        assert_eq!(b[3], "AK:SK");
    }

    #[test]
    fn s3_region_defaults_when_absent() {
        let mut t = s3();
        t.region = None;
        assert_eq!(t.auth_args()[1], "aws:amz:us-east-1:s3");
    }

    #[test]
    fn validate_walks_the_real_object_url() {
        // 基地址合法但拼完越界的情况必须被抓到——校验的必须是拼好的 URL
        let mut t = s3();
        t.bucket = None;
        assert!(t.validate().is_err(), "s3 缺 bucket 时拼接就会失败，validate 必须报出来");

        let mut t2 = webdav();
        t2.url = "ftp://dav.example.com/b/".into();
        assert!(t2.validate().is_err(), "非 http/https 必须被拒");

        assert!(webdav().validate().is_ok());
        assert!(s3().validate().is_ok());
    }

    #[test]
    fn non_http_urls_are_rejected() {
        let mut t = webdav();
        t.url = "file:///etc/passwd".into();
        let url = t.object_url("x").unwrap();
        // 断言的是**校验结果**，不是拼接结果：object_url 只管拼，协议白名单在
        // validate_remote_url（复用 webhook 那份，避免两套 URL 校验）
        assert!(
            validate_remote_url(&url).is_err(),
            "file:// 必须被拒（防 SSRF / 本地文件读取）"
        );
    }
}

/// 取出 XML 里 `<tag>...</tag>` 的全部值。
///
/// **不引 XML 库**：依赖预算只剩 1 位，而这里要解析的是我们自己发出的
/// LIST 响应——S3 ListObjectsV2 与 WebDAV multistatus 都是扁平结构。
/// 只认**精确标签名**（`Key` / `D:href` 等），不做通用 XML 解析；
/// 取不到就返回空（调用方按"远端没有产物"处理，不会误判）。
fn extract_tag_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(&open) {
        rest = &rest[i + open.len()..];
        match rest.find(&close) {
            Some(j) => {
                out.push(rest[..j].trim().to_string());
                rest = &rest[j + close.len()..];
            }
            None => break,
        }
    }
    out
}

/// 取 href / key 的最后一段（去掉尾部斜杠）。
fn last_segment(s: &str) -> String {
    s.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string()
}

/// 最小 percent-encode：只保留 RFC 3986 unreserved。
/// 前缀里可能有用户填的目录（`backups/2026`），不编码会让 query 断掉。
fn urlencode(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

#[cfg(test)]
mod list_tests {
    use super::*;

    fn dav() -> RemoteTarget {
        RemoteTarget {
            kind: RemoteKind::Webdav,
            url: "https://dav.example.com/backups/".into(),
            bucket: None,
            prefix: None,
            region: None,
            user: Some("u".into()),
            secret: Some("s".into()),
        }
    }

    fn s3() -> RemoteTarget {
        RemoteTarget {
            kind: RemoteKind::S3,
            url: "https://s3.example.com".into(),
            bucket: Some("bk".into()),
            prefix: Some("backups/".into()),
            region: Some("ap-east-1".into()),
            user: Some("ak".into()),
            secret: Some("sk".into()),
        }
    }

    #[test]
    fn extracts_s3_keys_and_takes_last_segment() {
        let xml = r#"<?xml version="1.0"?><ListBucketResult>
            <Contents><Key>backups/plan1-123.tar.gz</Key></Contents>
            <Contents><Key>backups/plan1-456.db</Key></Contents>
        </ListBucketResult>"#;
        let keys = extract_tag_values(xml, "Key");
        assert_eq!(keys.len(), 2);
        assert_eq!(last_segment(&keys[0]), "plan1-123.tar.gz");
        assert_eq!(last_segment(&keys[1]), "plan1-456.db");
    }

    #[test]
    fn extracts_webdav_hrefs_with_namespace_prefix() {
        let xml = r#"<D:multistatus xmlns:D="DAV:">
            <D:response><D:href>/dav/backups/</D:href></D:response>
            <D:response><D:href>/dav/backups/plan2-9.tar.gz</D:href></D:response>
        </D:multistatus>"#;
        let hrefs = extract_tag_values(xml, "D:href");
        assert_eq!(hrefs.len(), 2);
        assert_eq!(last_segment(&hrefs[0]), "backups");
        assert_eq!(last_segment(&hrefs[1]), "plan2-9.tar.gz");
    }

    /// ⭐ S3 单次只回 1000 个对象，截断后必须能接着翻页。
    #[test]
    fn reads_the_next_page_token_when_truncated() {
        let xml = r#"<ListBucketResult>
            <IsTruncated>true</IsTruncated>
            <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
        </ListBucketResult>"#;
        let t = s3().next_continuation(xml);
        assert_eq!(
            t.as_deref(),
            Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM="),
            "截断时必须拿到下一页令牌，否则列表会静默停在 1000 个"
        );
    }

    #[test]
    fn no_token_when_not_truncated() {
        let xml = r#"<ListBucketResult><IsTruncated>false</IsTruncated>
            <NextContinuationToken>ignored</NextContinuationToken></ListBucketResult>"#;
        assert_eq!(s3().next_continuation(xml), None);
    }

    /// 没有令牌却说截断（部分兼容实现会这样）：返回 None 而不是空串死循环。
    #[test]
    fn truncated_without_a_token_stops() {
        let xml = r#"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>"#;
        assert_eq!(s3().next_continuation(xml), None);
    }

    /// WebDAV 的 PROPFIND 没有分页——永远 None（否则会给 DAV 请求拼上 S3 参数）。
    #[test]
    fn webdav_never_paginates() {
        assert_eq!(dav().next_continuation("<IsTruncated>true</IsTruncated>"), None);
    }

    #[test]
    fn continuation_token_is_appended_and_encoded() {
        let (url, _) = s3()
            .list_request("plan7-", Some("ab/c="))
            .unwrap();
        assert!(url.contains("continuation-token=ab%2Fc%3D"), "{url}");
        assert!(url.contains("list-type=2"), "{url}");
    }

    #[test]
    fn empty_continuation_is_omitted() {
        let (url, _) = s3().list_request("plan7-", Some("  ")).unwrap();
        assert!(!url.contains("continuation-token"), "{url}");
    }

    /// 接线守卫：`list()` 必须**真的翻页**。
    ///
    /// `next_continuation` / `list_request` 两条单测都过了，不代表有人调用它们——
    /// 而"函数写了没人用"正是最难靠 review 发现的一类。用源码断言钉住接线；
    /// ⚠ 断言前剔除注释行（本文件注释里逐字写着 `next_continuation`）。
    #[test]
    fn list_follows_continuation_tokens() {
        let src = include_str!("remote_store.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: Vec<&str> = prod.lines().filter(|l| !l.trim_start().starts_with("//")).collect();
        let joined = code.join("\n");
        let start = joined.find("pub async fn list(").expect("list 必须存在");
        let rest = &joined[start..];
        let end = rest.find("\n    pub ").unwrap_or(rest.len());
        let block = &rest[..end];
        assert!(block.contains("for _ in 0..LIST_MAX_PAGES"), "list 必须翻页循环，否则远端超过 1000 个对象就静默截断");
        assert!(block.contains("self.next_continuation(&body)"), "list 必须取下一页令牌");
        assert!(block.contains("if token.is_none()"), "取不到令牌时必须停，不能死循环");
    }

    #[test]
    fn s3_list_url_encodes_the_prefix() {
        let (url, extra) = s3().list_request("plan7-", None).unwrap();
        assert_eq!(url, "https://s3.example.com/bk?list-type=2&prefix=backups%2Fplan7-");
        assert!(extra.is_empty(), "S3 不需要额外 header");
    }

    #[test]
    fn webdav_list_uses_propfind_depth_one() {
        let (url, extra) = dav().list_request("plan7-", None).unwrap();
        assert_eq!(url, "https://dav.example.com/backups/");
        let joined = extra.join(" ");
        assert!(joined.contains("PROPFIND"), "{joined}");
        assert!(joined.contains("Depth: 1"), "{joined}");
    }

    #[test]
    fn s3_without_bucket_is_rejected_before_any_network_call() {
        let mut t = s3();
        t.bucket = None;
        assert!(t.list_request("plan7-", None).is_err());
    }

    #[test]
    fn urlencode_keeps_unreserved_and_escapes_slashes() {
        assert_eq!(urlencode("plan7-"), "plan7-");
        assert_eq!(urlencode("a/b c"), "a%2Fb%20c");
    }
}
