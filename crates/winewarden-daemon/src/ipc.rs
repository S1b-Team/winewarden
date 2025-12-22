use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use time::OffsetDateTime;

use winewarden_core::ipc::{WineWardenRequest, WineWardenResponse, RunResult, StatusPayload};

use crate::store::EventStore;

pub struct DaemonState {
    pub started_at: OffsetDateTime,
    pub active_sessions: u32,
    pub last_session_id: Option<uuid::Uuid>,
    pub last_summary: Option<String>,
    #[allow(dead_code)]
    pub store: EventStore,
}

pub fn serve(
    socket_path: &Path,
    state: Arc<Mutex<DaemonState>>,
    handler: impl Fn(WineWardenRequest, &Arc<Mutex<DaemonState>>) -> Result<WineWardenResponse> + Send + Sync + 'static,
) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create socket dir {}", parent.display()))?;
    }
    if socket_path.exists() {
        fs::remove_file(socket_path)
            .with_context(|| format!("remove stale socket {}", socket_path.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind socket {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set socket permissions {}", socket_path.display()))?;

    for stream in listener.incoming() {
        let stream = stream?;
        check_peer_uid(&stream)?;
        let response = handle_connection(stream, &handler, &state)?;
        if let Some(response) = response {
            update_state(&state, &response);
        }
    }
    Ok(())
}

fn handle_connection(
    stream: UnixStream,
    handler: &impl Fn(WineWardenRequest, &Arc<Mutex<DaemonState>>) -> Result<WineWardenResponse>,
    state: &Arc<Mutex<DaemonState>>,
) -> Result<Option<WineWardenResponse>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        return Ok(None);
    }
    let request: WineWardenRequest = serde_json::from_str(&line).context("parse request")?;
    let response = handler(request, state)?;

    let mut writer = BufWriter::new(stream);
    let payload = serde_json::to_string(&response).context("serialize response")?;
    writer.write_all(payload.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    Ok(Some(response))
}

fn check_peer_uid(stream: &UnixStream) -> Result<()> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(anyhow::anyhow!("failed to read peer credentials"));
    }
    let current = unsafe { libc::geteuid() };
    if cred.uid != current {
        return Err(anyhow::anyhow!("unauthorized peer uid {}", cred.uid));
    }
    Ok(())
}

fn update_state(state: &Arc<Mutex<DaemonState>>, response: &WineWardenResponse) {
    let mut state = match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match response {
        WineWardenResponse::RunResult(RunResult { session_id, summary }) => {
            state.last_session_id = Some(*session_id);
            state.last_summary = Some(summary.clone());
        }
        WineWardenResponse::Status(StatusPayload { active_sessions, last_session_id, last_summary, .. }) => {
            state.active_sessions = *active_sessions;
            state.last_session_id = *last_session_id;
            state.last_summary = last_summary.clone();
        }
        _ => {}
    }
}
