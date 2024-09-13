use rustrc::{
    client::Client,
    //client::Config,
    ssh::SSHConfig,
    cmd,
};

use std::time::Duration;

#[tokio::main]
async fn main() -> rustrc::Result<()> {
    let ssh_config = SSHConfig::password("m00nl1g7", "127.0.0.1:22", "password123", Duration::from_secs(10)).await?;

    let mut client = Client::connect(ssh_config).await?;

    let out = client.exec(cmd!("ls -la")).await?;

    println!("{:?}", out.stdout);

    client.disconnect().await?;


    Ok(())
}
