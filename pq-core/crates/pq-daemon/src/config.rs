use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "sovereign-daemon", about = "Sovereign PQ Kernel Daemon")]
pub struct NodeConfig {
    #[arg(long, default_value = "/var/lib/sovereign")]
    pub data_dir: PathBuf,

    #[arg(long, default_value_t = 9050)]
    pub socks_port: u16,

    #[arg(long)]
    pub identity: Option<String>,
}

impl NodeConfig {
    pub fn validate_and_jail(&self) -> Result<(), &'static str> {
        if !self.data_dir.is_absolute() {
            return Err("data_dir must be an absolute path");
        }

        match fs::symlink_metadata(&self.data_dir) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err("data_dir is a symbolic link — refusing to follow (TOCTOU guard)");
                }
                if !meta.is_dir() {
                    return Err("data_dir exists but is not a directory");
                }
                let perms = meta.permissions().mode() & 0o777;
                if perms != 0o700 {
                    return Err("data_dir exists with unsafe permissions (expected 0700)");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.data_dir)
                    .map_err(|_| "failed to create data_dir")?;
                fs::set_permissions(&self.data_dir, fs::Permissions::from_mode(0o700))
                    .map_err(|_| "failed to set 0700 permissions on data_dir")?;
            }
            Err(_) => {
                return Err("failed to query symlink_metadata on data_dir");
            }
        }

        Ok(())
    }

    pub fn reputation_path(&self) -> PathBuf {
        self.data_dir.join("reputation.json")
    }

    pub fn sqlite_path(&self) -> PathBuf {
        self.data_dir.join("shards.db")
    }

    pub fn tor_state_dir(&self) -> PathBuf {
        self.data_dir.join("arti_state")
    }

    pub fn log_path(&self) -> PathBuf {
        self.data_dir.join("sovereign.log")
    }
}

pub const FAU_GUARD_PK: [u8; 32] = [0u8; 32];

pub fn get_trusted_manifest() -> &'static str {
    "{}"
}
