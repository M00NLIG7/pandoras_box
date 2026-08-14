use crate::types::{Share, ShareType};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

const SMB_CONFIG_PATHS: &[&str] = &[
    "/etc/samba/smb.conf",
    "/usr/local/samba/lib/smb.conf",
    "/usr/local/etc/smb.conf",
    "/opt/samba/etc/smb.conf",
];
const NFS_EXPORT_PATHS: &[&str] = &[
    "/etc/exports",
    "/usr/local/etc/exports",
    "/etc/nfs.conf/exports",
];

fn open_first(paths: &[&str], description: &str) -> io::Result<File> {
    let mut first_error = None;

    for path in paths {
        match File::open(path) {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                first_error.get_or_insert_with(|| {
                    io::Error::new(error.kind(), format!("failed to open {path}: {error}"))
                });
            }
        }
    }

    Err(first_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, description)))
}

fn push_smb_share(
    shares: &mut Vec<Share>,
    current_share: &mut Option<String>,
    has_path: &mut bool,
) {
    if *has_path {
        if let Some(share_name) = current_share.take() {
            shares.push(Share {
                share_type: ShareType::SMB,
                network_path: format!("//localhost/{share_name}"),
            });
        }
    } else {
        current_share.take();
    }
    *has_path = false;
}

fn parse_smb_shares(reader: impl BufRead) -> io::Result<Vec<Share>> {
    let mut shares = Vec::new();
    let mut current_share = None;
    let mut has_path = false;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();

        if trimmed.starts_with('#') || trimmed.starts_with(';') || trimmed.is_empty() {
            continue;
        }

        if let Some(section) = trimmed
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            push_smb_share(&mut shares, &mut current_share, &mut has_path);
            if !section.eq_ignore_ascii_case("global") && !section.eq_ignore_ascii_case("printers")
            {
                current_share = Some(section.to_string());
            }
            continue;
        }

        if current_share.is_some() {
            if let Some((key, value)) = trimmed.split_once('=') {
                if key.trim().eq_ignore_ascii_case("path") {
                    has_path = !value.trim().is_empty();
                }
            }
        }
    }

    push_smb_share(&mut shares, &mut current_share, &mut has_path);
    Ok(shares)
}

pub fn read_smb_shares() -> io::Result<Vec<Share>> {
    let file = open_first(SMB_CONFIG_PATHS, "SMB configuration file not found")?;
    parse_smb_shares(BufReader::new(file))
}

fn parse_nfs_shares(
    reader: impl BufRead,
    is_directory: impl Fn(&Path) -> bool,
) -> io::Result<Vec<Share>> {
    let mut shares = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(raw_path) = trimmed.split_whitespace().next() else {
            continue;
        };
        let clean_path = raw_path.trim_matches(['"', '\'']);
        let path = Path::new(clean_path);
        if !path.is_absolute() || clean_path.contains('*') || !is_directory(path) {
            continue;
        }

        shares.push(Share {
            share_type: ShareType::NFS,
            network_path: format!("nfs://localhost{clean_path}"),
        });
    }

    Ok(shares)
}

pub fn read_nfs_shares() -> io::Result<Vec<Share>> {
    let file = open_first(NFS_EXPORT_PATHS, "NFS exports file not found")?;
    parse_nfs_shares(BufReader::new(file), Path::is_dir)
}

pub fn shares() -> (Vec<Share>, Vec<String>) {
    let mut shares = Vec::new();
    let mut errors = Vec::new();

    match read_smb_shares() {
        Ok(smb_shares) => shares.extend(smb_shares),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!("SMB share inventory failed: {error}")),
    }
    match read_nfs_shares() {
        Ok(nfs_shares) => shares.extend(nfs_shares),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => errors.push(format!("NFS share inventory failed: {error}")),
    }

    (shares, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn parses_smb_shares_from_a_fixture() {
        let fixture = r#"
            [global]
            workgroup = WORKGROUP

            [documents]
            path = /srv/documents

            [missing-path]
            read only = yes

            [printers]
            path = /var/spool/samba

            [backups]
            PATH = /srv/backups
        "#;

        let shares = parse_smb_shares(Cursor::new(fixture)).expect("fixture should parse");
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].network_path, "//localhost/documents");
        assert_eq!(shares[1].network_path, "//localhost/backups");
    }

    #[test]
    fn parses_nfs_shares_from_a_fixture() {
        let root = tempdir().expect("tempdir should be created");
        let exported = root.path().join("exported");
        std::fs::create_dir(&exported).expect("export fixture should be created");
        let missing = root.path().join("missing");
        let fixture = format!(
            "# exports fixture\n\"{}\" *(ro)\n{} *(rw)\nrelative *(rw)\n",
            exported.display(),
            missing.display()
        );

        let shares =
            parse_nfs_shares(Cursor::new(fixture), Path::is_dir).expect("fixture should parse");
        assert_eq!(shares.len(), 1);
        assert_eq!(
            shares[0].network_path,
            format!("nfs://localhost{}", exported.display())
        );
    }
}
