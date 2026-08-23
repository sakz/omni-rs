use omni_config::wire::RuntimeConfigWire;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoredUser {
    pub email: String,
    #[serde(default)]
    pub uuid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedUsers {
    #[serde(default)]
    pub users: BTreeMap<String, StoredUser>,
}

#[derive(Debug)]
pub enum PersistError {
    Io(std::io::Error),
    Serde(serde_json::Error),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistError::Io(e) => write!(f, "{}", e),
            PersistError::Serde(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for PersistError {}

pub struct UserStore {
    path: PathBuf,
    data: RwLock<PersistedUsers>,
}

impl UserStore {
    pub async fn open(wire: &RuntimeConfigWire) -> Result<Arc<UserStore>, PersistError> {
        let path = PathBuf::from(
            wire.user_persist_path
                .clone()
                .unwrap_or_else(|| "users.json".to_string()),
        );
        let data = match tokio::fs::read(&path).await {
            Ok(bytes) => serde_json::from_slice::<PersistedUsers>(&bytes)
                .map_err(PersistError::Serde)
                .unwrap_or_default(),
            Err(_) => PersistedUsers::default(),
        };
        Ok(Arc::new(UserStore {
            path,
            data: RwLock::new(data),
        }))
    }

    pub async fn snapshot(&self) -> PersistedUsers {
        self.data.read().await.clone()
    }

    pub async fn upsert(&self, user: StoredUser) {
        let mut w = self.data.write().await;
        w.users.insert(user.email.clone(), user);
    }

    pub async fn clear(&self) -> usize {
        let mut w = self.data.write().await;
        let n = w.users.len();
        w.users.clear();
        n
    }

    pub async fn flush(&self) -> Result<(), PersistError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
        }
        let snap = self.data.read().await.clone();
        let bytes = serde_json::to_vec_pretty(&snap).map_err(PersistError::Serde)?;
        tokio::fs::write(&self.path, bytes)
            .await
            .map_err(PersistError::Io)
    }
}
