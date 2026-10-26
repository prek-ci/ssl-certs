use std::ffi::{OsStr, OsString};
use std::fs;
use std::process::Command;

use pki_types::CertificateDer;
use pki_types::pem::PemObject;
use ssl_certs::{ErrorKind, load_certs_from_env, load_certs_from_paths};

/// A malformed PEM block must not discard other certificates in the same
/// bundle. The file that caused the decoding error must appear in diagnostics.
#[test]
fn partial_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let file = tempfile::NamedTempFile::new()?;
    let valid = include_str!("one-existing-ca.pem");
    let expected = CertificateDer::from_pem_slice(valid.as_bytes())?;
    let invalid = "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n";
    for contents in [format!("{invalid}{valid}"), format!("{valid}{invalid}")] {
        fs::write(file.path(), contents)?;
        let result = load_certs_from_paths(Some(file.path()), None);
        assert_eq!(result.certs.as_slice(), std::slice::from_ref(&expected));
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].path, file.path());
        assert!(matches!(result.errors[0].kind, ErrorKind::Pem(_)));
    }
    Ok(())
}

/// Configuration presence survives empty and failed loads, while multiple
/// configured directories and a file contribute one deduplicated custom store.
/// Each environment is tested in its own process without mutating this process.
#[test]
fn environment_sources() -> Result<(), Box<dyn std::error::Error>> {
    const CASE: &str = "SSL_CERTS_TEST_CASE";
    if let Ok(case) = std::env::var(CASE) {
        let result = load_certs_from_env();
        let (certs, errors) = match case.as_str() {
            "unset" | "empty-file-value" | "empty-dir-value" | "empty-values" => {
                assert!(result.is_none());
                return Ok(());
            }
            "empty-file" | "empty-dir" | "empty-entries" => (0, 0),
            "missing-paths" => (0, 2),
            "invalid-pem" => (0, 1),
            "combined" | "empty-file-valid-dirs" => (2, 0),
            "missing-file-valid-dirs" => (2, 1),
            _ => return Err(format!("unknown case: {case}").into()),
        };
        let result = result.ok_or("configured sources must return Some")?;
        assert_eq!(result.certs.len(), certs);
        assert_eq!(result.errors.len(), errors);
        return Ok(());
    }

    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let empty_file = root.join("empty.pem");
    let empty_dir = root.join("empty");
    let valid_file = root.join("valid.pem");
    let invalid_file = root.join("invalid.pem");
    let dir1 = root.join("first");
    let dir2 = root.join("second");
    let missing = root.join("missing");
    fs::write(&empty_file, "")?;
    fs::write(
        &invalid_file,
        "-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n",
    )?;
    fs::create_dir(&empty_dir)?;
    fs::create_dir(&dir1)?;
    fs::create_dir(&dir2)?;
    fs::write(&valid_file, include_bytes!("one-existing-ca.pem"))?;
    fs::copy(&valid_file, dir1.join("duplicate.pem"))?;
    fs::write(
        dir2.join("certificate"),
        include_bytes!("badssl-com-chain.pem"),
    )?;
    let dirs = std::env::join_paths([dir1.as_path(), dir2.as_path()])?;
    let empty_entries = std::env::join_paths([OsStr::new(""), OsStr::new("")])?;
    let empty = OsString::new();

    for (case, file, dir) in [
        ("unset", None, None),
        ("empty-file-value", Some(empty.as_os_str()), None),
        ("empty-dir-value", None, Some(empty.as_os_str())),
        (
            "empty-values",
            Some(empty.as_os_str()),
            Some(empty.as_os_str()),
        ),
        ("empty-file", Some(empty_file.as_os_str()), None),
        ("invalid-pem", Some(invalid_file.as_os_str()), None),
        ("empty-dir", None, Some(empty_dir.as_os_str())),
        ("empty-entries", None, Some(empty_entries.as_os_str())),
        (
            "missing-paths",
            Some(missing.as_os_str()),
            Some(missing.as_os_str()),
        ),
        (
            "combined",
            Some(valid_file.as_os_str()),
            Some(dirs.as_os_str()),
        ),
        (
            "empty-file-valid-dirs",
            Some(empty.as_os_str()),
            Some(dirs.as_os_str()),
        ),
        (
            "missing-file-valid-dirs",
            Some(missing.as_os_str()),
            Some(dirs.as_os_str()),
        ),
    ] {
        let mut child = Command::new(std::env::current_exe()?);
        child
            .args(["--exact", "environment_sources", "--nocapture"])
            .current_dir(root)
            .env_remove("SSL_CERT_FILE")
            .env_remove("SSL_CERT_DIR")
            .env(CASE, case);
        if let Some(file) = file {
            child.env("SSL_CERT_FILE", file);
        }
        if let Some(dir) = dir {
            child.env("SSL_CERT_DIR", dir);
        }
        let output = child.output()?;
        assert!(
            output.status.success(),
            "{case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    Ok(())
}
