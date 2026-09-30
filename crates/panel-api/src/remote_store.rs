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
