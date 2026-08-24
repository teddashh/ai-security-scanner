use crate::registry::EngineRegistry;
use crate::storage::Storage;

pub struct AppState {
    pub storage: Storage,
    pub engines: EngineRegistry,
}
