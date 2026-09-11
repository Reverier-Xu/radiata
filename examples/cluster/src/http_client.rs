//! A minimal HTTP/1.1 JSON client, used to fetch join tokens from the
//! bootstrap node and to answer the same calls from axum handlers. A
//! real customer service would use reqwest; this keeps the demo
//! dependency tree small while staying async-clean.

use serde_json::Value;
use tokio::{
  io::{AsyncReadExt as _, AsyncWriteExt as _},
  net::TcpStream,
};

async fn request(addr: &str, request: String) -> std::io::Result<String> {
  let mut stream = TcpStream::connect(addr).await?;
  stream.write_all(request.as_bytes()).await?;
  let raw = read_response(&mut stream).await?;
  Ok(raw)
}

async fn read_response(stream: &mut TcpStream) -> std::io::Result<String> {
  let mut raw = Vec::new();
  // Read until connection close (connection: close on every request).
  let mut buf = [0u8; 4096];
  loop {
    let read = stream.read(&mut buf).await?;
    if read == 0 {
      break;
    }
    raw.extend_from_slice(&buf[..read]);
  }
  Ok(String::from_utf8_lossy(&raw).into_owned())
}

fn body_of(raw: &str) -> std::io::Result<Value> {
  let body = raw
    .split_once("\r\n\r\n")
    .map(|(_, body)| body)
    .ok_or_else(|| std::io::Error::other("malformed http response"))?;
  if raw
    .to_ascii_lowercase()
    .contains("transfer-encoding: chunked")
  {
    let mut decoded = String::new();
    let mut rest = body;
    loop {
      let Some((size_line, remainder)) = rest.split_once("\r\n") else {
        break;
      };
      let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
      if size == 0 {
        break;
      }
      let end = remainder.len().min(size);
      decoded.push_str(&remainder[..end]);
      rest = remainder
        .get(end..)
        .unwrap_or_default()
        .trim_start_matches("\r\n");
    }
    return serde_json::from_str(&decoded)
      .map_err(|error| std::io::Error::other(format!("bad json: {error}")));
  }
  serde_json::from_str(body).map_err(|error| std::io::Error::other(format!("bad json: {error}")))
}

pub async fn get_json(addr: &str, path: &str) -> std::io::Result<Value> {
  let wire = format!(
    "GET {path} HTTP/1.1\r\nhost: {addr}\r\nconnection: close\r\naccept: application/json\r\n\r\n"
  );
  let raw = request(addr, wire).await?;
  body_of(&raw)
}

#[allow(dead_code)]
pub async fn post_json(addr: &str, path: &str, body: &Value) -> std::io::Result<Value> {
  let payload = serde_json::to_vec(body)?;
  let wire = format!(
    "POST {path} HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
    payload.len()
  );
  let raw = request(addr, wire).await?;
  body_of(&raw)
}
