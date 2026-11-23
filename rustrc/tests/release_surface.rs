const MANIFEST: &str = include_str!("../Cargo.toml");
const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const SSH_SOURCE: &str = include_str!("../src/ssh/mod.rs");

#[test]
fn first_release_exposes_only_ssh_without_build_time_downloads() {
    for removed_surface in [
        "winexe",
        "download_embed_macro",
        "reqwest",
        "danger_accept_invalid_certs",
        "pub mod telnet",
        "pub mod winrm",
    ] {
        assert!(
            !MANIFEST.contains(removed_surface) && !LIB_SOURCE.contains(removed_surface),
            "removed release surface reappeared: {removed_surface}"
        );
    }
}

#[test]
fn ssh_file_transfer_cannot_open_remote_listener_fallback() {
    for forbidden_implementation in [
        "TcpStream::connect",
        "netsh advfirewall firewall add",
        "0.0.0.0",
        "transfer_file.bat",
        "batch_transfer_file",
    ] {
        assert!(
            !SSH_SOURCE.contains(forbidden_implementation),
            "SSH release surface must remain SFTP-only: {forbidden_implementation}"
        );
    }
}
