use rustrc::{
    client::Client,
    cmd,
    ssh::{HostKeyPolicy, SSHConfig},
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = std::env::var("RUSTRC_USERNAME").unwrap_or_else(|_| "root".to_string());
    let password = std::env::var("RUSTRC_PASSWORD")?;
    let socket = std::env::var("RUSTRC_SOCKET")?;
    let ssh_config = SSHConfig::password_with_policy(
        username,
        password,
        socket,
        Duration::from_secs(10),
        HostKeyPolicy::RequireKnownHosts,
    )
    .await?;

    let mut client = Client::connect(ssh_config).await?;
    let output = client.exec(&cmd!("uname", "-a")).await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    client.disconnect().await?;
    Ok(())
}
