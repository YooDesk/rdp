//! RDCleanPath协商与TLS字节桥；证书校验遵守统一开关，浏览器IronRDP负责NLA与解码。
use crate::{business::remote::RemoteSession, connections::ConnectionTarget};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use ironrdp_rdcleanpath::{RDCleanPathPdu, VERSION_1};
use rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

/// 目标的精确RDCleanPath地址格式。
pub fn destination(target: &ConnectionTarget) -> String {
    if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

#[derive(Clone, Debug)]
struct CertificateInfo {
    chain: Vec<Vec<u8>>,
    sha256: String,
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    needs_confirmation: bool,
}
#[derive(Debug)]
struct Verifier {
    system: Arc<WebPkiServerVerifier>,
    pin: Option<String>,
    observed: Mutex<Option<CertificateInfo>>,
}

// 只交付固定失败分类，避免把底层诊断中的证书/网络载荷暴露到会话错误。
// 保留验证根因，不能将所有握手错误抹成同一个泛化消息。
fn tls_failure_class(error: &std::io::Error) -> &'static str {
    let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<rustls::Error>())
    else {
        return "transport";
    };
    match error {
        rustls::Error::General(message) => match message.as_str() {
            "RDP certificate is expired or not yet valid" => "certificate_time",
            "RDP certificate does not permit server authentication" => "certificate_usage",
            "RDP certificate fingerprint mismatch" => "certificate_pin",
            "RDP certificate confirmation required" => "certificate_confirmation",
            "invalid RDP certificate validation time" => "certificate_clock",
            _ => "certificate_policy",
        },
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding) => {
            "certificate_encoding"
        }
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature) => {
            "certificate_signature"
        }
        rustls::Error::InvalidCertificate(_) => "certificate_validation",
        rustls::Error::PeerIncompatible(_) => "peer_incompatible",
        rustls::Error::PeerMisbehaved(_) => "peer_protocol",
        rustls::Error::AlertReceived(_) => "peer_alert",
        _ => "tls_protocol",
    }
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let validation_time = i64::try_from(now.as_secs())
            .ok()
            .and_then(|seconds| x509_parser::time::ASN1Time::from_timestamp(seconds).ok())
            .ok_or_else(|| {
                rustls::Error::General("invalid RDP certificate validation time".into())
            })?;
        if !cert.validity().is_valid_at(validation_time) {
            return Err(rustls::Error::General(
                "RDP certificate is expired or not yet valid".into(),
            ));
        }
        let usage = cert.extended_key_usage().map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if usage.is_some_and(|usage| !usage.value.server_auth && !usage.value.any) {
            return Err(rustls::Error::General(
                "RDP certificate does not permit server authentication".into(),
            ));
        }
        let digest = format!("{:x}", Sha256::digest(leaf.as_ref()));
        let trusted = self
            .system
            .verify_server_cert(leaf, intermediates, name, ocsp, now);
        // Trust and name can be explicitly confirmed; other certificate failures cannot.
        if matches!(&trusted, Err(err) if !matches!(
            err,
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
                | rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. }
            )
        )) {
            return trusted;
        }
        let needs_confirmation = self.pin.is_none() && trusted.is_err();
        let date = |seconds: i64| {
            crate::timefmt::format_rfc3339(
                std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(seconds.max(0) as u64),
            )
        };
        *self.observed.lock().unwrap() = Some(CertificateInfo {
            chain: std::iter::once(leaf.to_vec())
                .chain(intermediates.iter().map(|c| c.to_vec()))
                .collect(),
            sha256: digest.clone(),
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            not_before: date(cert.validity().not_before.timestamp()),
            not_after: date(cert.validity().not_after.timestamp()),
            needs_confirmation,
        });
        if let Some(expected) = &self.pin {
            if expected != &digest {
                return Err(rustls::Error::General(
                    "RDP certificate fingerprint mismatch".into(),
                ));
            }
            return Ok(ServerCertVerified::assertion());
        }
        trusted.map_err(|_| rustls::Error::General("RDP certificate confirmation required".into()))
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.system.verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.system.verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.system.supported_verify_schemes()
    }
}

/// 严格读取初始请求，服务端响应字段/任意地址/preconnection blob均不允许。
pub fn parse_request(bytes: &[u8], target: &ConnectionTarget) -> Result<Vec<u8>, String> {
    if bytes.len() > 65536 {
        return Err("RDCleanPath request exceeds limit".into());
    }
    let pdu = RDCleanPathPdu::from_der(bytes).map_err(|_| "invalid RDCleanPath DER")?;
    if pdu.version != VERSION_1
        || pdu.destination.as_deref() != Some(destination(target).as_str())
        || pdu.error.is_some()
        || pdu.server_cert_chain.is_some()
        || pdu.server_addr.is_some()
        || pdu.server_auth.is_some()
        || pdu.preconnection_blob.is_some()
    {
        return Err("RDCleanPath request does not match the configured target".into());
    }
    let x224 = pdu
        .x224_connection_pdu
        .ok_or("X.224 negotiation missing")?
        .into_bytes();
    if x224.len() < 19
        || x224.len() > 16384
        || x224[0] != 3
        || x224[1] != 0
        || u16::from_be_bytes([x224[2], x224[3]]) as usize != x224.len()
        || usize::from(x224[4]) + 5 != x224.len()
        || x224[5] != 0xe0
    {
        return Err("invalid X.224 request".into());
    }
    let n = x224.len() - 8;
    const TLS_PROTOCOLS: u32 = 1 | 2 | 8;
    let protocols = u32::from_le_bytes(x224[n + 4..].try_into().unwrap());
    if x224[n] != 1
        || u16::from_le_bytes([x224[n + 2], x224[n + 3]]) != 8
        || protocols == 0
        || protocols & !TLS_PROTOCOLS != 0
    {
        return Err("RDP requires TLS-capable negotiation".into());
    }
    Ok(x224)
}
async fn connect_tls(
    target: &ConnectionTarget,
    x224: &[u8],
    verifier: Arc<dyn ServerCertVerifier>,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>, String), String> {
    let mut tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| "RDP target timed out")?
    .map_err(|_| "RDP target connection failed")?;
    tcp.set_nodelay(true)
        .map_err(|_| "cannot configure RDP TCP")?;
    let address = tcp
        .peer_addr()
        .map_err(|_| "RDP address missing")?
        .to_string();
    let response = tokio::time::timeout(Duration::from_secs(10), async {
        tcp.write_all(x224).await?;
        let mut header = [0u8; 4];
        tcp.read_exact(&mut header).await?;
        let total = u16::from_be_bytes([header[2], header[3]]) as usize;
        if header[0] != 3 || header[1] != 0 || !(19..=16384).contains(&total) {
            return Err(std::io::Error::other("invalid X.224 confirm"));
        }
        let mut result = vec![0; total];
        result[..4].copy_from_slice(&header);
        tcp.read_exact(&mut result[4..]).await?;
        Ok::<_, std::io::Error>(result)
    })
    .await
    .map_err(|_| "RDP negotiation timed out")?
    .map_err(|_| "invalid RDP negotiation response")?;
    let n = response.len() - 8;
    let protocol = u32::from_le_bytes(response[n + 4..].try_into().unwrap());
    let requested = u32::from_le_bytes(x224[x224.len() - 4..].try_into().unwrap());
    if usize::from(response[4]) + 5 != response.len()
        || response[5] != 0xd0
        || response[n] != 2
        || u16::from_le_bytes([response[n + 2], response[n + 3]]) != 8
        || !matches!(protocol, 1 | 2 | 8)
        || protocol & requested == 0
    {
        return Err("RDP security negotiation was rejected; no downgrade is attempted".into());
    }
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let name = ServerName::try_from(target.host.clone()).map_err(|_| "invalid RDP server name")?;
    let tls = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .map_err(|_| "RDP TLS timed out")?
    .map_err(|error| format!("RDP TLS validation failed: {}", tls_failure_class(&error)))?;
    Ok((tls, response, address))
}
async fn system_verifier() -> Result<Arc<WebPkiServerVerifier>, String> {
    tokio::task::spawn_blocking(|| {
        let certs = rustls_native_certs::load_native_certs();
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(certs.certs);
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|_| "cannot load system certificate trust".to_string())
    })
    .await
    .map_err(|_| "certificate trust task failed".to_string())?
}

async fn relay_bytes<T>(socket: &mut WebSocket, tunnel: T) -> Result<(), String>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut outgoing, mut incoming) = socket.split();
    let (mut reader, mut writer) = tokio::io::split(tunnel);
    let (pongs, mut pending_pongs) = tokio::sync::mpsc::channel(8);
    // 任一方向的写入都可能填满对端窗口。两个泵保持反向读取，
    // 让画面确认和剪贴板请求能够释放背压，避免互相等待。
    let to_browser = async move {
        let mut buffer = vec![0; 65536];
        loop {
            let message = tokio::select! {
                pong = pending_pongs.recv() => match pong {
                    Some(bytes) => Message::Pong(bytes),
                    None => return Ok::<(), String>(()),
                },
                result = reader.read(&mut buffer) => match result {
                    Ok(0) => return Ok(()),
                    Ok(size) => Message::Binary(buffer[..size].to_vec().into()),
                    Err(_) => return Err("RDP connection interrupted".into()),
                },
            };
            tokio::time::timeout(Duration::from_secs(15), outgoing.send(message))
                .await
                .map_err(|_| "RDP browser write timed out".to_string())?
                .map_err(|_| "RDP browser disconnected".to_string())?;
        }
    };
    let to_target = async move {
        while let Some(message) = incoming.next().await {
            match message {
                Ok(Message::Binary(bytes)) => {
                    // TLS may buffer the final bytes of a write. RDP can wait
                    // for them before sending the next clipboard request.
                    tokio::time::timeout(Duration::from_secs(15), async {
                        writer.write_all(&bytes).await?;
                        writer.flush().await
                    })
                    .await
                    .map_err(|_| "RDP target write timed out".to_string())?
                    .map_err(|_| "RDP target disconnected".to_string())?;
                }
                Ok(Message::Ping(bytes)) => {
                    tokio::time::timeout(Duration::from_secs(10), pongs.send(bytes))
                        .await
                        .map_err(|_| "RDP browser write timed out".to_string())?
                        .map_err(|_| "RDP browser disconnected".to_string())?;
                }
                Ok(Message::Pong(_)) => {}
                Ok(Message::Close(_)) => return Ok(()),
                _ => return Err("invalid RDP stream frame".into()),
            }
        }
        Ok(())
    };
    tokio::select! {
        result = to_browser => result,
        result = to_target => result,
    }
}

/// 已授权WS上的一次RDP会话；取消/断开会关闭TLS，不触发自动重新登录。
pub async fn stream(mut socket: WebSocket, session: Arc<RemoteSession>) {
    let operation = async {
        let initial = tokio::time::timeout(Duration::from_secs(20), socket.recv())
            .await
            .map_err(|_| "RDCleanPath request timed out")?;
        let Some(Ok(Message::Binary(bytes))) = initial else {
            return Err("RDCleanPath binary request required".to_string());
        };
        let x224 = parse_request(&bytes, &session.target)?;
        let (tls, response, address, certs) = if !crate::tls_policy::verification_enabled()? {
            // 默认不校验证书，不读取系统 CA、不弹确认；仍使用 TLS 加密及握手签名。
            let (tls, response, address) = connect_tls(
                &session.target,
                &x224,
                crate::tls_policy::ignore_certificate_errors(),
            )
            .await?;
            let certs = tls
                .get_ref()
                .1
                .peer_certificates()
                .ok_or("RDP certificate missing")?
                .iter()
                .map(|certificate| certificate.to_vec())
                .collect();
            (tls, response, address, certs)
        } else {
            let system = system_verifier().await?;
            let pin = if session.target.certificate_sha256.is_empty() {
                None
            } else {
                Some(session.target.certificate_sha256.to_ascii_lowercase())
            };
            let verifier = Arc::new(Verifier {
                system: system.clone(),
                pin: pin.clone(),
                observed: Mutex::new(None),
            });
            let first = connect_tls(&session.target, &x224, verifier.clone()).await;
            match first {
                Ok((tls, response, address)) => {
                    let observed = verifier
                        .observed
                        .lock()
                        .unwrap()
                        .clone()
                        .ok_or("RDP certificate missing")?;
                    (tls, response, address, observed.chain)
                }
                Err(error) => {
                    let observed = verifier.observed.lock().unwrap().clone();
                    let Some(observed) = observed.filter(|c| c.needs_confirmation && pin.is_none())
                    else {
                        return Err(error);
                    };
                    let payload = json!({"host":session.target.host,"port":session.target.port,"subject":observed.subject,"issuer":observed.issuer,"sha256":observed.sha256,"not_before":observed.not_before,"not_after":observed.not_after,"validation_errors":["untrusted_certificate_or_name_mismatch"]});
                    let answer = session.ask("certificate", payload).await?;
                    if answer["decision"] != "accept_once" {
                        return Err("RDP certificate rejected".into());
                    }
                    let confirmed = Arc::new(Verifier {
                        system,
                        pin: Some(observed.sha256),
                        observed: Mutex::new(None),
                    });
                    let (tls, response, address) =
                        connect_tls(&session.target, &x224, confirmed.clone()).await?;
                    let chain = confirmed
                        .observed
                        .lock()
                        .unwrap()
                        .as_ref()
                        .ok_or("RDP certificate missing")?
                        .chain
                        .clone();
                    (tls, response, address, chain)
                }
            }
        };
        let response = RDCleanPathPdu::new_response(address, response, certs)
            .and_then(|p| p.to_der())
            .map_err(|_| "cannot encode RDCleanPath response")?;
        crate::http::send_ws_message(&mut socket, Message::Binary(response.into()))
            .await
            .map_err(|_| "RDP browser disconnected")?;
        session.transition("active");
        relay_bytes(&mut socket, tls).await
    };
    let result = tokio::select! {biased; _=session.cancelled()=>Ok(()),result=operation=>result};
    if let Err(error) = result {
        *session.error.lock().unwrap() = Some(error);
        session.transition("failed");
        if let Ok(bytes) = RDCleanPathPdu::new_http_error(502).to_der() {
            let _ = crate::http::send_ws_message(&mut socket, Message::Binary(bytes.into())).await;
        }
    }
    let _ = crate::http::send_ws_message(&mut socket, Message::Close(None)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn duplex_forwarding_reads_while_target_write_is_backpressured() {
        use axum::{routing::get, Router};
        use futures_util::{SinkExt, StreamExt};

        let (proxy, mut target) = tokio::io::duplex(1024);
        let proxy = Arc::new(Mutex::new(Some(tokio::io::BufWriter::new(proxy))));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/",
            get(move |upgrade: axum::extract::ws::WebSocketUpgrade| {
                let proxy = proxy.lock().unwrap().take().unwrap();
                async move {
                    upgrade.on_upgrade(move |mut socket| async move {
                        let _ = relay_bytes(&mut socket, proxy).await;
                    })
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (mut browser, _) = tokio_tungstenite::connect_async(format!("ws://{address}/"))
            .await
            .unwrap();
        let exercise = async {
            // Like TLS, the target writer can buffer a short final fragment.
            // The target waits for it before requesting the next fragment.
            browser
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    vec![19; 23].into(),
                ))
                .await
                .unwrap();
            let mut short = [0; 23];
            target.read_exact(&mut short).await.unwrap();
            assert_eq!(short, [19; 23]);
            browser
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    vec![81; 16384].into(),
                ))
                .await
                .unwrap();
            // 先消费一个字节，证明代理已开始超出目标窗口的大写入。
            let mut first = [0];
            target.read_exact(&mut first).await.unwrap();
            assert_eq!(first, [81]);
            let producer = async {
                target.write_all(&vec![37; 16384]).await.unwrap();
                let mut rest = vec![0; 16383];
                target.read_exact(&mut rest).await.unwrap();
                assert!(rest.iter().all(|value| *value == 81));
            };
            let consumer = async {
                let mut received = Vec::new();
                while received.len() < 16384 {
                    if let tokio_tungstenite::tungstenite::Message::Binary(bytes) =
                        browser.next().await.unwrap().unwrap()
                    {
                        received.extend_from_slice(&bytes);
                    }
                }
                assert_eq!(received, vec![37; 16384]);
                browser.close(None).await.unwrap();
            };
            tokio::join!(producer, consumer);
        };
        let result = tokio::time::timeout(Duration::from_secs(2), exercise).await;
        server.abort();
        result.expect("short writes must flush and a blocked write must not stop reverse traffic");
    }
    #[test]
    fn rdp_certificate_confirmation_cannot_override_invalid_usage_time_or_signature() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = rcgen::generate_simple_self_signed(vec!["trusted.example".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.cert.der().clone()).unwrap();
        let system = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["rdp.example".into()]).unwrap();
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
        let key = rcgen::KeyPair::generate().unwrap();
        let client_only = params.self_signed(&key).unwrap();
        let valid = rcgen::generate_simple_self_signed(vec!["rdp.example".into()]).unwrap();
        let after_expiry = UnixTime::since_unix_epoch(Duration::from_secs(253_402_300_799));
        let name = ServerName::try_from("rdp.example").unwrap();
        for (cert, now) in [
            (client_only.der(), UnixTime::now()),
            (valid.cert.der(), after_expiry),
            (valid.cert.der(), UnixTime::now()),
        ] {
            for pin in [None, Some(format!("{:x}", Sha256::digest(cert.as_ref())))] {
                let verifier = Verifier {
                    system: system.clone(),
                    pin,
                    observed: Mutex::new(None),
                };
                assert!(verifier
                    .verify_server_cert(cert, &[], &name, &[], now)
                    .is_err());
                assert!(verifier.observed.lock().unwrap().is_none());
            }
        }
    }

    #[test]
    fn certificate_requires_trust_or_exact_pin() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut root_params =
            rcgen::CertificateParams::new(vec!["trusted.example".into()]).unwrap();
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test trust root");
        let root = root_params
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();
        let system = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let leaf = rcgen::generate_simple_self_signed(vec!["rdp.example".into()]).unwrap();
        let name = ServerName::try_from("rdp.example").unwrap();
        let now = UnixTime::now();
        let make = |pin| Verifier {
            system: system.clone(),
            pin,
            observed: Mutex::new(None),
        };
        let untrusted = make(None);
        let rejected = untrusted
            .verify_server_cert(leaf.cert.der(), &[], &name, &[], now)
            .unwrap_err();
        assert!(
            untrusted
                .observed
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|cert| cert.needs_confirmation),
            "unexpected certificate rejection: {rejected:?}"
        );
        let correct = make(Some(format!(
            "{:x}",
            Sha256::digest(leaf.cert.der().as_ref())
        )));
        assert!(correct
            .verify_server_cert(leaf.cert.der(), &[], &name, &[], now)
            .is_ok());
        let changed = make(Some("0".repeat(64)));
        assert!(changed
            .verify_server_cert(leaf.cert.der(), &[], &name, &[], now)
            .is_err());
        assert!(
            !changed
                .observed
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .needs_confirmation
        );
    }
    fn target() -> ConnectionTarget {
        serde_json::from_value(
            json!({"id":"test-rdp","label":"Test","protocol":"rdp","host":"192.0.2.1","port":3389}),
        )
        .unwrap()
    }
    fn x224(protocol: u32) -> Vec<u8> {
        let mut bytes = vec![3, 0, 0, 19, 14, 0xe0, 0, 0, 0, 0, 0, 1, 0, 8, 0];
        bytes.extend_from_slice(&protocol.to_le_bytes());
        bytes
    }
    #[tokio::test]
    #[ignore = "requires YOODESK_RDP_TEST_HOST for a dedicated RDP target; sends no credentials"]
    async fn real_rdp_negotiation_binds_retry_to_observed_certificate() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut target = target();
        target.host = std::env::var("YOODESK_RDP_TEST_HOST").expect("RDP test host");
        let system = system_verifier().await.unwrap();
        let make = |pin| {
            Arc::new(Verifier {
                system: system.clone(),
                pin,
                observed: Mutex::new(None),
            })
        };
        let greeting = x224(0x0b);
        let probe = make(None);
        let first = connect_tls(&target, &greeting, probe.clone()).await;
        let observed = probe.observed.lock().unwrap().clone().unwrap_or_else(|| {
            panic!(
                "RDP peer did not present a usable certificate: {:?}",
                first.err()
            )
        });
        let wrong = make(Some("0".repeat(64)));
        assert!(connect_tls(&target, &greeting, wrong).await.is_err());
        let pinned = make(Some(observed.sha256.clone()));
        let (_stream, response, _) = connect_tls(&target, &greeting, pinned.clone())
            .await
            .unwrap();
        assert_eq!(response[5], 0xd0);
        assert_eq!(
            pinned.observed.lock().unwrap().as_ref().unwrap().sha256,
            observed.sha256
        );
    }

    #[test]
    fn bundled_ironrdp_browser_greeting_matches_bridge_contract() {
        // Captured from bundled IronRDP WASM in Chromium with CredSSP enabled.
        let wire = concat!(
            "305aa00402020d3ea2100c0e3132372e302e302e313a33333839",
            "a3110c0f6c6f63616c2d6163636573732d7632a62d042b",
            "0300002b26e00000000000436f6f6b69653a206d737473686173683d",
            "70726f62650d0a010008000b000000"
        );
        let wire: Vec<u8> = (0..wire.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&wire[offset..offset + 2], 16).unwrap())
            .collect();
        let mut target = target();
        target.host = "127.0.0.1".into();
        let greeting = parse_request(&wire, &target).unwrap();
        assert_eq!(&greeting[greeting.len() - 4..], &[0x0b, 0, 0, 0]);
    }

    #[test]
    fn rdcleanpath_binds_destination_and_requires_tls() {
        let target = target();
        let request = |host, protocol, pcb| {
            RDCleanPathPdu::new_request(x224(protocol), host, "public-marker".into(), pcb)
                .unwrap()
                .to_der()
                .unwrap()
        };
        assert!(parse_request(&request(destination(&target), 3, None), &target).is_ok());
        assert!(parse_request(&request("other.example:3389".into(), 3, None), &target).is_err());
        assert!(parse_request(&request(destination(&target), 0, None), &target).is_err());
        assert!(parse_request(&request(destination(&target), 5, None), &target).is_err());
        assert!(parse_request(
            &request(destination(&target), 3, Some("blob".into())),
            &target
        )
        .is_err());
        assert!(parse_request(&[0; 65537], &target).is_err());
        assert!(parse_request(&[0x30, 0xff], &target).is_err());
    }
    #[test]
    fn rejects_server_response_and_malformed_tpkt() {
        let target = target();
        let response = RDCleanPathPdu::new_response(destination(&target), x224(3), [vec![1]])
            .unwrap()
            .to_der()
            .unwrap();
        assert!(parse_request(&response, &target).is_err());
        let mut bytes = x224(3);
        bytes[3] = 20;
        let request =
            RDCleanPathPdu::new_request(bytes, destination(&target), "marker".into(), None)
                .unwrap()
                .to_der()
                .unwrap();
        assert!(parse_request(&request, &target).is_err());
        let mut bytes = x224(3);
        bytes[4] -= 1;
        let request =
            RDCleanPathPdu::new_request(bytes, destination(&target), "marker".into(), None)
                .unwrap()
                .to_der()
                .unwrap();
        assert!(parse_request(&request, &target).is_err());
        let mut ipv6 = target;
        ipv6.host = "::1".into();
        assert_eq!(destination(&ipv6), "[::1]:3389");
    }
}
