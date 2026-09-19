use anyhow::{Context, Result, ensure};
use object::Object;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub(crate) struct Snapshot {
    pub id: String,
    pub directory: tempfile::TempDir,
    pub path: PathBuf,
    pub sha256: String,
    pub size: i64,
    pub architecture: String,
    pub format: String,
}

pub(crate) fn create(source: &Path, root: &Path) -> Result<Snapshot> {
    ensure!(source.is_file(), "binary path must be a regular file");
    let mut source = File::open(source).context("cannot open binary")?;
    ensure!(
        source.metadata()?.is_file(),
        "binary path must be a regular file"
    );
    std::fs::create_dir_all(root)?;
    let id = uuid::Uuid::new_v4().to_string();
    let directory = tempfile::Builder::new()
        .prefix(&id)
        .rand_bytes(0)
        .tempdir_in(root)?;
    let path = directory.path().join("program.bin");
    let mut destination = File::create(&path)?;
    let mut digest = Sha256::new();
    let mut size = 0i64;
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        destination.write_all(&buffer[..count])?;
        digest.update(&buffer[..count]);
        size = size
            .checked_add(count as i64)
            .context("binary exceeds supported size")?;
    }
    destination.sync_all()?;
    drop(destination);
    // Parse the completed copy, never the mutable source. ReadCache loads metadata
    // ranges on demand without mapping or reading the entire binary into a Vec.
    let cache = object::read::ReadCache::new(File::open(&path)?);
    let binary = object::File::parse(&cache)
        .context("unsupported binary: expected ELF, PE, Mach-O, COFF or XCOFF")?;
    let architecture = format!("{:?}", binary.architecture());
    let format = format!("{:?}", binary.format());
    let mut permissions = std::fs::metadata(&path)?.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(&path, permissions)?;
    #[cfg(unix)]
    {
        File::open(directory.path())?.sync_all()?;
        File::open(root)?.sync_all()?;
    }
    Ok(Snapshot {
        id,
        path: path.canonicalize()?,
        directory,
        sha256: hex::encode(digest.finalize()),
        size,
        architecture,
        format,
    })
}
