use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use directories::ProjectDirs;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug)]
pub struct TokenStore {
    service: String,
    state_path: PathBuf,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct StoredState {
    pub node_id: Uuid,
    pub private_key: String,
    pub public_key: String,
    #[serde(default)]
    pub server_host: String,
}

impl TokenStore {
    pub fn new(org: &str, app: &str, service: &str) -> std::io::Result<Self> {
        let proj = ProjectDirs::from("com", org, app)
            .ok_or_else(|| std::io::Error::other("No project dirs"))?;

        let dir = proj.data_local_dir();
        fs::create_dir_all(dir)?;

        debug!(
            "creating identity store in {}",
            dir.join("state.json").display()
        );

        Ok(Self {
            service: service.to_string(),
            state_path: dir.join("state.json"),
        })
    }

    pub fn save_identity(
        &self,
        node_id: Uuid,
        private_key: String,
        public_key: String,
    ) -> anyhow::Result<()> {
        let state = StoredState {
            node_id,
            private_key,
            public_key,
            server_host: self.service.clone(),
        };

        self.save_state(&state)
    }

    pub fn load(&self) -> anyhow::Result<StoredState> {
        debug!("loading node identity");

        let state = self.load_state()?.unwrap_or_default();

        if !state.server_host.is_empty() && state.server_host != self.service {
            anyhow::bail!(
                "Server mismatch: identity is for '{}' but attempting to connect to '{}'",
                state.server_host,
                self.service
            );
        }

        if state.node_id == Uuid::nil() {
            anyhow::bail!("stored node_id is nil; run login first")
        }

        validate_b64_len(&state.private_key, 32, "private_key")?;
        validate_b64_len(&state.public_key, 32, "public_key")?;

        Ok(state)
    }

    pub fn delete(&self) -> std::io::Result<()> {
        self.delete_state_file()
    }

    fn load_state(&self) -> anyhow::Result<Option<StoredState>> {
        self.load_state_from_file()
    }

    fn save_state(&self, state: &StoredState) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(state).map_err(io_other)?;
        atomic_write(&self.state_path, &bytes)
    }

    fn load_state_from_file(&self) -> anyhow::Result<Option<StoredState>> {
        match fs::read(&self.state_path) {
            Ok(bytes) => match serde_json::from_slice::<StoredState>(&bytes) {
                Ok(s) => Ok(Some(s)),
                Err(e) => {
                    warn!(
                        "Failed to deserialize state from {:?}: {}. Resetting state.",
                        self.state_path, e
                    );
                    Ok(None)
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn delete_state_file(&self) -> std::io::Result<()> {
        match fs::remove_file(&self.state_path) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn validate_b64_len(value: &str, expected_len: usize, field: &str) -> anyhow::Result<()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("failed to decode {}", field))?;

    if decoded.len() != expected_len {
        anyhow::bail!(
            "{} decoded to {} bytes, expected {}",
            field,
            decoded.len(),
            expected_len
        );
    }

    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("No parent dir"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if dir.exists()
            && let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        {
            warn!("Could not set directory permissions to 0o700: {}", e);
        }
    }

    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }

    tmp.persist(path).map_err(|e| e.error)?;
    info!("State file persisted to {:?}", path);
    Ok(())
}

fn io_other<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
