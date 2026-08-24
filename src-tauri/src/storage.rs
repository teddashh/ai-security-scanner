use crate::domain::{AssessmentCase, CaseSummary};
use crate::error::{AppError, AppResult};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CaseEvent {
    pub sequence: i64,
    pub case_id: String,
    pub event_type: String,
    pub occurred_at: String,
    pub payload_json: String,
}

pub struct Storage {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> AppResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(&path)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "secure_delete", "ON")?;
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;

        let storage = Self {
            path,
            connection: Mutex::new(connection),
        };
        storage.migrate()?;
        storage.restrict_permissions()?;
        Ok(storage)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connection(&self) -> AppResult<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| AppError::Storage("database lock was poisoned".into()))
    }

    fn migrate(&self) -> AppResult<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cases (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                organization_name TEXT NOT NULL,
                status TEXT NOT NULL,
                is_demo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                document_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_cases_updated_at
                ON cases(updated_at DESC);

            CREATE TABLE IF NOT EXISTS case_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_case_events_case_sequence
                ON case_events(case_id, sequence);

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO schema_migrations(version, applied_at)
            VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
            "#,
        )?;
        Ok(())
    }

    #[cfg(unix)]
    fn restrict_permissions(&self) -> AppResult<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    #[cfg(not(unix))]
    fn restrict_permissions(&self) -> AppResult<()> {
        Ok(())
    }

    pub fn save_case(&self, case: &AssessmentCase, event_type: &str) -> AppResult<()> {
        let document = serde_json::to_string(case)?;
        let status = serde_json::to_string(&case.status)?
            .trim_matches('"')
            .to_string();
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;

        transaction.execute(
            r#"
            INSERT INTO cases (
                id, title, organization_name, status, is_demo,
                created_at, updated_at, document_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                organization_name = excluded.organization_name,
                status = excluded.status,
                is_demo = excluded.is_demo,
                updated_at = excluded.updated_at,
                document_json = excluded.document_json
            "#,
            params![
                case.id,
                case.title,
                case.profile.organization_name,
                status,
                case.is_demo,
                case.created_at.to_rfc3339(),
                case.updated_at.to_rfc3339(),
                document,
            ],
        )?;

        transaction.execute(
            r#"
            INSERT INTO case_events(case_id, event_type, occurred_at, payload_json)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                case.id,
                event_type,
                Utc::now().to_rfc3339(),
                serde_json::json!({ "status": case.status }).to_string(),
            ],
        )?;

        transaction.commit()?;
        Ok(())
    }

    pub fn get_case(&self, id: &str) -> AppResult<AssessmentCase> {
        let connection = self.connection()?;
        let document: Option<String> = connection
            .query_row(
                "SELECT document_json FROM cases WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()?;

        let document = document.ok_or_else(|| AppError::CaseNotFound(id.to_owned()))?;
        Ok(serde_json::from_str(&document)?)
    }

    pub fn list_cases(&self) -> AppResult<Vec<CaseSummary>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT document_json FROM cases ORDER BY updated_at DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut cases = Vec::new();

        for row in rows {
            let document = row?;
            let case: AssessmentCase = serde_json::from_str(&document).map_err(|error| {
                AppError::Storage(format!("stored case could not be decoded: {error}"))
            })?;
            cases.push(CaseSummary::from(&case));
        }

        Ok(cases)
    }

    pub fn set_selected_case(&self, id: Option<&str>) -> AppResult<()> {
        let connection = self.connection()?;
        match id {
            Some(id) => {
                connection.execute(
                    r#"
                    INSERT INTO app_settings(key, value) VALUES ('selected_case_id', ?1)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    "#,
                    [id],
                )?;
            }
            None => {
                connection.execute(
                    "DELETE FROM app_settings WHERE key = 'selected_case_id'",
                    [],
                )?;
            }
        }
        Ok(())
    }

    pub fn selected_case_id(&self) -> AppResult<Option<String>> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT value FROM app_settings WHERE key = 'selected_case_id'",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn list_case_events(&self, case_id: &str) -> AppResult<Vec<CaseEvent>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT sequence, case_id, event_type, occurred_at, payload_json
            FROM case_events
            WHERE case_id = ?1
            ORDER BY sequence ASC
            "#,
        )?;
        let rows = statement.query_map([case_id], |row| {
            Ok(CaseEvent {
                sequence: row.get(0)?,
                case_id: row.get(1)?,
                event_type: row.get(2)?,
                occurred_at: row.get(3)?,
                payload_json: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Permanently removes one exact case document and its event history.
    /// Artifact files are handled by the case service so their case-scoped path
    /// can be resolved and reported separately.
    pub fn delete_case(&self, case_id: &str) -> AppResult<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE id = ?1)",
            [case_id],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(AppError::CaseNotFound(case_id.to_owned()));
        }
        transaction.execute("DELETE FROM cases WHERE id = ?1", [case_id])?;
        transaction.execute(
            "DELETE FROM app_settings WHERE key = 'selected_case_id' AND value = ?1",
            [case_id],
        )?;
        transaction.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AssessmentCase, DataClass, OrganizationProfile};

    fn sample_case() -> AssessmentCase {
        AssessmentCase::new(
            "Test case".into(),
            OrganizationProfile {
                organization_name: "Example Co".into(),
                employee_range: "11-50".into(),
                data_classes: vec![DataClass::PersonallyIdentifiableInformation],
                notes: None,
            },
        )
    }

    #[test]
    fn case_round_trip_and_selection() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let case = sample_case();

        storage.save_case(&case, "case.created").expect("save");
        storage
            .set_selected_case(Some(&case.id))
            .expect("selection");

        let loaded = storage.get_case(&case.id).expect("load");
        assert_eq!(loaded.title, case.title);
        assert_eq!(storage.list_cases().expect("list").len(), 1);
        assert_eq!(
            storage.selected_case_id().expect("selected"),
            Some(case.id.clone())
        );
        assert_eq!(storage.list_case_events(&case.id).expect("events").len(), 1);
    }

    #[test]
    fn deletion_is_exact_and_cascades_case_events() {
        let directory = tempfile::tempdir().expect("temp directory");
        let storage = Storage::open(directory.path().join("casework.db")).expect("storage");
        let first = sample_case();
        let mut second = sample_case();
        second.id = "case-to-keep".into();
        second.title = "Keep me".into();
        storage
            .save_case(&first, "case.created")
            .expect("save first");
        storage
            .save_case(&second, "case.created")
            .expect("save second");
        storage
            .set_selected_case(Some(&first.id))
            .expect("select first");

        storage.delete_case(&first.id).expect("delete first");

        assert!(matches!(
            storage.get_case(&first.id),
            Err(AppError::CaseNotFound(_))
        ));
        assert_eq!(storage.list_case_events(&first.id).expect("events"), vec![]);
        assert_eq!(
            storage.get_case(&second.id).expect("second").title,
            "Keep me"
        );
        assert_eq!(storage.selected_case_id().expect("selection"), None);
        assert!(matches!(
            storage.delete_case(&first.id),
            Err(AppError::CaseNotFound(_))
        ));
    }
}
