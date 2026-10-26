use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::{env, fmt, fs, io};

use pki_types::CertificateDer;
use pki_types::pem::{self, PemObject};

const ENV_CERT_FILE: &str = "SSL_CERT_FILE";
const ENV_CERT_DIR: &str = "SSL_CERT_DIR";

/// Load certificates from the paths specified in the environment variables
/// `SSL_CERT_FILE` and `SSL_CERT_DIR`.
///
/// Returns `None` when both variables are unset or empty. Otherwise returns
/// `Some`, even when the configured paths are missing, inaccessible, or contain
/// no certificates. This lets callers distinguish default trust from an
/// explicitly configured, possibly empty custom trust store.
///
/// `SSL_CERT_DIR` may contain multiple paths, separated by `:` on Unix or `;`
/// on Windows. Empty entries are ignored. A non-empty value containing only
/// separators still selects an empty custom trust store.
///
/// Certificates from all configured paths are combined and deduplicated. Loading
/// errors are collected without discarding certificates from other entries.
/// No system or bundled certificates are loaded.
pub fn load_certs_from_env() -> Option<CertificateResult> {
    let cert_file = env::var_os(ENV_CERT_FILE)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let cert_dirs = env::var_os(ENV_CERT_DIR).filter(|value| !value.is_empty());
    if cert_file.is_none() && cert_dirs.is_none() {
        return None;
    }
    let cert_dirs = match cert_dirs {
        Some(dirs) => env::split_paths(&dirs)
            .filter(|path| !path.as_os_str().is_empty())
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };

    Some(load_certs_from_paths_internal(
        cert_file.as_deref(),
        &cert_dirs,
    ))
}

/// Load certificates from the given paths.
///
/// If both are `None`, returns an empty [`CertificateResult`].
///
/// Files must contain PEM-encoded certificates. Text outside certificate blocks
/// is ignored. PEM decoding errors are reported in [`CertificateResult::errors`]
/// without discarding other certificates. The decoded DER is returned as-is;
/// validating the certificates is the caller's responsibility.
///
/// The directory is scanned non-recursively, including regular files regardless
/// of their names or extensions. Symlinks are followed; dangling symlinks are
/// ignored. File and directory certificates are combined and deduplicated.
///
/// I/O and parsing errors include the affected path and do not discard other
/// certificates. An empty result is allowed and is not itself an error.
pub fn load_certs_from_paths(file: Option<&Path>, dir: Option<&Path>) -> CertificateResult {
    let dirs = match dir {
        Some(d) => vec![d],
        None => Vec::new(),
    };

    load_certs_from_paths_internal(file, dirs.as_ref())
}

fn load_certs_from_paths_internal(
    file: Option<&Path>,
    dirs: &[impl AsRef<Path>],
) -> CertificateResult {
    let mut out = CertificateResult::default();
    if file.is_none() && dirs.is_empty() {
        return out;
    }

    if let Some(cert_file) = file {
        load_pem_certs(cert_file, &mut out);
    }

    for cert_dir in dirs {
        load_pem_certs_from_dir(cert_dir.as_ref(), &mut out);
    }

    out.certs.sort_unstable_by(|a, b| a.cmp(b));
    out.certs.dedup();
    out
}

/// Load certificate from certificate directory (what OpenSSL calls CAdir)
fn load_pem_certs_from_dir(dir: &Path, out: &mut CertificateResult) {
    let dir_reader = match fs::read_dir(dir) {
        Ok(reader) => reader,
        Err(err) => {
            out.io_error(err, dir, "opening directory");
            return;
        }
    };

    for entry in dir_reader {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                out.io_error(err, dir, "reading directory entries");
                continue;
            }
        };

        let path = entry.path();

        // `openssl rehash` used to create this directory uses symlinks. So,
        // make sure we resolve them.
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Dangling symlink
                continue;
            }
            Err(e) => {
                out.io_error(e, &path, "failed to open file");
                continue;
            }
        };

        if metadata.is_file() {
            load_pem_certs(&path, out);
        }
    }
}

fn load_pem_certs(path: &Path, out: &mut CertificateResult) {
    let iter = match CertificateDer::pem_file_iter(path) {
        Ok(iter) => iter,
        Err(err) => {
            out.pem_error(err, path);
            return;
        }
    };

    for result in iter {
        match result {
            Ok(cert) => out.certs.push(cert),
            Err(err) => out.pem_error(err, path),
        }
    }
}

/// Certificates and errors collected from the configured files and directories.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct CertificateResult {
    /// Deduplicated certificate bytes decoded from PEM, without DER validation.
    /// This may be empty even when loading encountered no errors.
    pub certs: Vec<CertificateDer<'static>>,
    /// Any errors encountered while loading certificates.
    pub errors: Vec<Error>,
}

impl CertificateResult {
    /// Return the found certificates if no error occurred, otherwise panic.
    #[track_caller]
    pub fn expect(self, msg: &str) -> Vec<CertificateDer<'static>> {
        match self.errors.is_empty() {
            true => self.certs,
            false => panic!("{msg}: {:?}", self.errors),
        }
    }

    /// Return the found certificates if no error occurred, otherwise panic.
    #[track_caller]
    pub fn unwrap(self) -> Vec<CertificateDer<'static>> {
        match self.errors.is_empty() {
            true => self.certs,
            false => panic!(
                "errors occurred while loading certificates: {:?}",
                self.errors
            ),
        }
    }

    fn pem_error(&mut self, err: pem::Error, path: &Path) {
        self.errors.push(Error {
            context: "failed to read PEM from file",
            path: path.to_owned(),
            kind: match err {
                pem::Error::Io(err) => ErrorKind::Io(err),
                _ => ErrorKind::Pem(err),
            },
        });
    }

    fn io_error(&mut self, err: io::Error, path: &Path, context: &'static str) {
        self.errors.push(Error {
            context,
            path: path.to_owned(),
            kind: ErrorKind::Io(err),
        });
    }
}

#[non_exhaustive]
#[derive(Debug)]
pub enum ErrorKind {
    Io(io::Error),
    Pem(pem::Error),
}

#[derive(Debug)]
pub struct Error {
    pub context: &'static str,
    /// The file or directory that caused this error.
    pub path: PathBuf,
    pub kind: ErrorKind,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match &self.kind {
            ErrorKind::Io(err) => err,
            ErrorKind::Pem(err) => err,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.context)?;
        match &self.kind {
            ErrorKind::Io(err) => err.fmt(f),
            ErrorKind::Pem(err) => err.fmt(f),
        }?;
        write!(f, " at '{}'", self.path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    #[cfg(unix)]
    use std::fs::Permissions;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn deduplication() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let cert1 = include_str!("../tests/badssl-com-chain.pem");
        let cert2 = include_str!("../tests/one-existing-ca.pem");
        let file_path = temp_dir.path().join("ca-certificates.crt");
        let dir_path = temp_dir.path().to_path_buf();

        {
            let mut file = File::create(&file_path).unwrap();
            write!(file, "{cert1}").unwrap();
            write!(file, "{cert2}").unwrap();
        }

        {
            // Duplicate (already in `file_path`)
            let mut file = File::create(dir_path.join("71f3bb26.0")).unwrap();
            write!(file, "{cert1}").unwrap();
        }

        {
            // Duplicate (already in `file_path`)
            let mut file = File::create(dir_path.join("912e7cd5.0")).unwrap();
            write!(file, "{cert2}").unwrap();
        }

        let result = load_certs_from_paths(Some(&file_path), None);
        assert_eq!(result.certs.len(), 2);

        let result = load_certs_from_paths(None, Some(&dir_path));
        assert_eq!(result.certs.len(), 2);

        let result = load_certs_from_paths(Some(&file_path), Some(&dir_path));
        assert_eq!(result.certs.len(), 2);
    }

    #[test]
    fn malformed_file_from_env() {
        // Certificate parser tries to extract certs from file ignoring
        // invalid sections.
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new(file!()), &mut result);
        assert_eq!(result.certs.len(), 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn from_env_missing_file() {
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new("no/such/file"), &mut result);
        match &first_error(&result).kind {
            ErrorKind::Io(inner) => assert_eq!(inner.kind(), io::ErrorKind::NotFound),
            _ => panic!("unexpected error {:?}", result.errors),
        }
    }

    #[test]
    fn from_env_missing_dir() {
        let mut result = CertificateResult::default();
        load_pem_certs_from_dir(Path::new("no/such/directory"), &mut result);
        match &first_error(&result).kind {
            ErrorKind::Io(inner) => assert_eq!(inner.kind(), io::ErrorKind::NotFound),
            _ => panic!("unexpected error {:?}", result.errors),
        }
    }

    #[test]
    #[cfg(unix)]
    fn from_env_with_non_regular_and_empty_file() {
        let mut result = CertificateResult::default();
        load_pem_certs(Path::new("/dev/null"), &mut result);
        assert_eq!(result.certs.len(), 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn from_env_bad_dir_perms() {
        // Create a temp dir that we can't read from.
        let temp_dir = tempfile::TempDir::new().unwrap();
        fs::set_permissions(temp_dir.path(), Permissions::from_mode(0o000)).unwrap();

        test_cert_paths_bad_perms(None, &[temp_dir.path()]);
    }

    #[test]
    #[cfg(unix)]
    fn from_env_bad_file_perms() {
        // Create a tmp dir with a file inside that we can't read from.
        let temp_dir = tempfile::TempDir::new().unwrap();
        let file_path = temp_dir.path().join("unreadable.pem");
        let cert_file = File::create(&file_path).unwrap();
        cert_file
            .set_permissions(Permissions::from_mode(0o000))
            .unwrap();

        test_cert_paths_bad_perms(Some(&file_path), &[]);
    }

    #[cfg(unix)]
    fn test_cert_paths_bad_perms(file: Option<&Path>, dirs: &[&Path]) {
        let result = load_certs_from_paths_internal(file, dirs);

        if let (None, true) = (file, dirs.is_empty()) {
            panic!("only one of file or dir should be set");
        };

        let error = first_error(&result);
        match &error.kind {
            ErrorKind::Io(inner) => {
                assert_eq!(inner.kind(), io::ErrorKind::PermissionDenied);
                inner
            }
            _ => panic!("unexpected error {:?}", result.errors),
        };
    }

    fn first_error(result: &CertificateResult) -> &Error {
        result.errors.first().unwrap()
    }
}
