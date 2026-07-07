//! Interactive DMKG UI - a tiny std-only HTTP server.
//!
//! Serves a single-page vanilla-JS frontend and a small JSON API over a shared
//! [`DkgSession`]. No web framework, no async runtime: one thread per connection,
//! one request per connection. Intended for local use with `n <= 10`.
//!
//! Run: `cargo run --release --features ui --bin dkg_ui`

use aggregatable_dkg::sim::{
    CommonReferenceView, DkgSession, Malice, ParticipantView, PublicKeyView, Snapshot,
    ZTreeLevelView, ZTreeNodeView,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

// Frontend assets are bundled into the binary - a single `cargo run`, no files to ship.
const INDEX_HTML: &str = include_str!("web/index.html");
const APP_JS: &str = include_str!("web/app.js");
const STYLE_CSS: &str = include_str!("web/style.css");

/// The shared, mutable session state.
struct AppState {
    session: DkgSession,
    n: usize,
    degree: usize,
    malice: BTreeMap<usize, Malice>,
}

fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // Default configuration: 4 honest participants, threshold t = 2.
    let n = 4;
    let degree = 2;
    let malice = BTreeMap::new();
    let session =
        DkgSession::new(n, Some(degree), malice.clone()).expect("default session must be valid");
    let state = Arc::new(Mutex::new(AppState {
        session,
        n,
        degree,
        malice,
    }));

    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("Failed to bind {}: {}", addr, e);
        std::process::exit(1);
    });

    println!("\nPartially Aggregatable DMKG - interactive UI");
    println!("Open  http://{}  in your browser.", addr);
    println!("Press Ctrl-C to stop.\n");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                std::thread::spawn(move || {
                    let _ = handle(stream, state);
                });
            }
            Err(e) => eprintln!("connection error: {}", e),
        }
    }
}

fn handle(mut stream: TcpStream, state: Arc<Mutex<AppState>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);

    // Request line.
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    // Headers (we only care about Content-Length).
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    // Body.
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    let body = String::from_utf8_lossy(&body).to_string();

    let (status, content_type, payload) = route(&method, &path, &body, &state);
    write_response(&mut stream, status, content_type, &payload)
}

fn route(
    method: &str,
    path: &str,
    body: &str,
    state: &Arc<Mutex<AppState>>,
) -> (&'static str, &'static str, Vec<u8>) {
    match (method, path) {
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", INDEX_HTML.into()),
        ("GET", "/app.js") => (
            "200 OK",
            "application/javascript; charset=utf-8",
            APP_JS.into(),
        ),
        ("GET", "/style.css") => ("200 OK", "text/css; charset=utf-8", STYLE_CSS.into()),
        ("GET", "/api/state") => {
            let st = state.lock().unwrap();
            json_response(snapshot_json(&st.session.snapshot()))
        }
        ("POST", "/api/configure") => {
            let parsed: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let n = parsed.get("n").and_then(|v| v.as_u64()).unwrap_or(4) as usize;
            let degree = parsed
                .get("degree")
                .and_then(|v| v.as_u64())
                .map(|d| d as usize);
            let malice = parse_malice(&parsed);
            match DkgSession::new(n, degree, malice.clone()) {
                Ok(session) => {
                    let mut st = state.lock().unwrap();
                    st.n = n;
                    st.degree = session_degree(&session);
                    st.malice = malice;
                    st.session = session;
                    json_response(snapshot_json(&st.session.snapshot()))
                }
                Err(e) => json_response(json!({ "error": e })),
            }
        }
        ("POST", "/api/advance") => {
            let mut st = state.lock().unwrap();
            if let Err(e) = st.session.advance() {
                return json_response(json!({ "error": e }));
            }
            json_response(snapshot_json(&st.session.snapshot()))
        }
        ("POST", "/api/reset") => {
            let mut st = state.lock().unwrap();
            let (n, degree, malice) = (st.n, st.degree, st.malice.clone());
            match DkgSession::new(n, Some(degree), malice) {
                Ok(session) => {
                    st.session = session;
                    json_response(snapshot_json(&st.session.snapshot()))
                }
                Err(e) => json_response(json!({ "error": e })),
            }
        }
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            b"not found".to_vec(),
        ),
    }
}

/// Parse the per-participant malice from a configure request. Accepts the new
/// `malice` object (`{ "1": "z", "2": "pedersen" }`) and, as a fallback, the
/// legacy `malicious` array of ids (each interpreted as `both`).
fn parse_malice(parsed: &Value) -> BTreeMap<usize, Malice> {
    let mut out = BTreeMap::new();
    if let Some(obj) = parsed.get("malice").and_then(|v| v.as_object()) {
        for (id, kind) in obj.iter() {
            if let (Ok(id), Some(kind)) = (id.parse::<usize>(), kind.as_str()) {
                let m = Malice::from_tag(kind);
                if m != Malice::Honest {
                    out.insert(id, m);
                }
            }
        }
    }
    if let Some(arr) = parsed.get("malicious").and_then(|v| v.as_array()) {
        for x in arr.iter().filter_map(|x| x.as_u64()) {
            out.entry(x as usize).or_insert(Malice::Both);
        }
    }
    out
}

/// Read back the effective degree from a fresh session's snapshot.
fn session_degree(session: &DkgSession) -> usize {
    session.snapshot().degree
}

fn json_response(value: Value) -> (&'static str, &'static str, Vec<u8>) {
    (
        "200 OK",
        "application/json; charset=utf-8",
        value.to_string().into_bytes(),
    )
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ct}\r\nContent-Length: {len}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        status = status,
        ct = content_type,
        len = body.len(),
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

// ---- Snapshot -> JSON ----------------------------------------------------

fn snapshot_json(s: &Snapshot) -> Value {
    json!({
        "phase": s.phase,
        "phaseIndex": s.phase_index,
        "canAdvance": s.can_advance,
        "nextPhase": s.next_phase,
        "n": s.n,
        "degree": s.degree,
        "reconstructionThreshold": s.reconstruction_threshold,
        "malicious": s.malicious,
        "malice": s.malice.iter().map(|(id, tag)| json!({"id": id, "kind": tag})).collect::<Vec<_>>(),
        "qagg": s.qagg,
        "qual": s.qual,
        "complaints": s.complaints.iter().map(|(d, c)| json!({"dealer": d, "complainer": c})).collect::<Vec<_>>(),
        "publicKey": s.public_key.as_ref().map(pk_json),
        "participants": s.participants.iter().map(participant_json).collect::<Vec<_>>(),
        "log": s.log,
        "zTree": s.z_tree.iter().map(z_level_json).collect::<Vec<_>>(),
        "zTotalLevels": s.z_total_levels,
        "zLevelsDone": s.z_levels_done,
        "zRoot": s.z_root,
        "zTranscriptBroadcast": s.z_transcript_broadcast,
        "zApprovals": s.z_approvals.iter().map(|(id, ok)| json!({"id": id, "approved": ok})).collect::<Vec<_>>(),
        "common": common_json(&s.common),
    })
}

fn common_json(c: &CommonReferenceView) -> Value {
    json!({
        "gG1": c.g_g1,
        "hG2": c.h_g2,
        "u1": c.u_1,
        "pedG1": c.ped_g1,
        "pedG2": c.ped_g2,
        "pedH1": c.ped_h1,
        "pedH2": c.ped_h2,
        "elgamalBase": c.elgamal_base,
        "domainSize": c.domain_size,
    })
}

fn z_level_json(lv: &ZTreeLevelView) -> Value {
    json!({
        "level": lv.level,
        "isLeafLevel": lv.is_leaf_level,
        "isRootLevel": lv.is_root_level,
        "description": lv.description,
        "nodes": lv.nodes.iter().map(z_node_json).collect::<Vec<_>>(),
    })
}

fn z_node_json(nd: &ZTreeNodeView) -> Value {
    json!({
        "realParticipants": nd.real_participants,
        "aggregator": nd.aggregator,
        "leafOk": nd.leaf_ok,
        "position": nd.position,
    })
}

fn pk_json(pk: &PublicKeyView) -> Value {
    json!({
        "c1": pk.c1,
        "c2": pk.c2,
        "c3": pk.c3,
        "reconstructedOk": pk.reconstructed_ok,
    })
}

fn participant_json(p: &ParticipantView) -> Value {
    json!({
        "id": p.id,
        "malicious": p.malicious,
        "malice": p.malice,
        "maliceLabel": p.malice_label,
        "inQagg": p.in_qagg,
        "complaintsAgainst": p.complaints_against,
        "inQual": p.in_qual,
        "disqualifiedReason": p.disqualified_reason,
        "public": p.public.iter().map(|f| json!({"label": f.label, "value": f.value})).collect::<Vec<_>>(),
        "private": p.private.iter().map(|f| json!({"label": f.label, "value": f.value})).collect::<Vec<_>>(),
        "communication": p.communication.iter().map(|f| json!({"label": f.label, "value": f.value})).collect::<Vec<_>>(),
    })
}
