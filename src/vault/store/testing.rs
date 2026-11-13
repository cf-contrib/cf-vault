//! Test-only file store, compiled only with the `test-store` cargo feature.
//!
//! It keeps each entry as a plain file and exists so integration tests can drive the real binary
//! without a keychain. It is never part of a release build and is selected only by the
//! `CF_VAULT_STORE_DIR` environment variable.

use std::{fs, path::PathBuf};

use crate::vault::{auth::redact::Secret, store::SecretStore, Error, Result};

/// One file per account inside a directory.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// Opens (creating it if needed) the directory of the store.
    pub fn open(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir).map_err(|e| Error::io("cannot create the test store", e))?;
        Ok(FileStore { dir })
    }

    fn path(&self, account: &str) -> PathBuf {
        self.dir.join(format!("{account}.json"))
    }
}

impl SecretStore for FileStore {
    fn get(&self, account: &str) -> Result<Option<Secret>> {
        match fs::read_to_string(self.path(account)) {
            Ok(text) => Ok(Some(Secret::new(text))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io("cannot read the test store", e)),
        }
    }

    fn set(&self, account: &str, value: &Secret) -> Result<()> {
        fs::write(self.path(account), value.expose())
            .map_err(|e| Error::io("cannot write the test store", e))
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match fs::remove_file(self.path(account)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io("cannot delete from the test store", e)),
        }
    }
}
