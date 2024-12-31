use std::io::{Read, Write};
use std::net::IpAddr;
use tokio::net::{lookup_host, TcpStream, ToSocketAddrs};
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use std::time::Duration;
use rand::Rng;

const SMB_COM_NEGOTIATE: u8 = 0x72;

fn write_u16_le(v: u16) -> [u8; 2] {
    [v as u8, (v >> 8) as u8]
}

fn write_u32_be(v: u32) -> [u8; 4] {
    [(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8]
}

fn read_u32_be(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24) | ((bytes[1] as u32) << 16) | ((bytes[2] as u32) << 8) | (bytes[3] as u32)
}

struct SMBCommand {
    command: u8,
    parameters: Vec<u8>,
    data: Vec<u8>,
}

impl SMBCommand {
    fn new(command: u8, parameters: Vec<u8>, data: Vec<u8>) -> Self {
        SMBCommand { command, parameters, data }
    }

    fn pack(&self) -> Vec<u8> {
        let mut packed = Vec::new();
        packed.push((self.parameters.len() / 2) as u8);
        packed.extend_from_slice(&self.parameters);
        packed.extend_from_slice(&write_u16_le(self.data.len() as u16));
        packed.extend_from_slice(&self.data);
        packed
    }
}

struct NewSMBPacket {
    command: u8,
    flags1: u8,
    flags2: u16,
    pid: u16,
    mid: u16,
    smb_command: Option<SMBCommand>,
}

impl NewSMBPacket {
    fn new(command: u8, flags1: u8, flags2: u16) -> Self {
        NewSMBPacket {
            command,
            flags1,
            flags2,
            pid: rand::thread_rng().gen_range(1..=65535),
            mid: rand::thread_rng().gen_range(1..=65535),
            smb_command: None,
        }
    }

    fn add_command(&mut self, command: SMBCommand) {
        self.smb_command = Some(command);
    }

    fn pack(&self) -> Vec<u8> {
        let mut packed = Vec::new();
        packed.extend_from_slice(b"\xffSMB");
        packed.push(self.command);
        packed.push(0); // ErrorClass
        packed.push(0); // Reserved
        packed.extend_from_slice(&[0, 0]); // ErrorCode
        packed.push(self.flags1);
        packed.extend_from_slice(&write_u16_le(self.flags2));
        packed.extend_from_slice(&[0, 0]); // PIDHigh
        packed.extend_from_slice(&[0; 8]); // SecurityFeatures
        packed.extend_from_slice(&[0, 0]); // Reserved
        packed.extend_from_slice(&write_u16_le(0xffff)); // TID
        packed.extend_from_slice(&write_u16_le(self.pid));
        packed.extend_from_slice(&[0, 0]); // UID
        packed.extend_from_slice(&write_u16_le(self.mid));

        if let Some(cmd) = &self.smb_command {
            packed.extend_from_slice(&cmd.pack());
        }

        packed
    }
}

struct NetBIOSSessionService {
    stream: TcpStream,
}

impl NetBIOSSessionService {
    async fn connect<A: ToSocketAddrs>(addr: A, timeout: Duration) -> std::io::Result<Self> {
        let addr = lookup_host(addr).await?.next().ok_or_else(|| std::io::ErrorKind::AddrNotAvailable)?;

        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr)).await??;
        // let stream = TcpStream::connect_timeout(&addr.to_socket_addrs().next().unwrap(), timeout)?;
        Ok(NetBIOSSessionService { stream })
    }

    async fn send_packet(&mut self, data: &[u8]) -> crate::Result<()> {
        self.stream.write_all(&write_u32_be(data.len() as u32)).await;
        self.stream.write_all(data).await;
        Ok(())
    }

    async fn recv_packet(&mut self) -> std::io::Result<Vec<u8>> {
        let mut length_buf = [0u8; 4];
        self.stream.read_exact(&mut length_buf).await;
        let length = read_u32_be(&length_buf);
        let mut data = vec![0; length as usize];
        self.stream.read_exact(&mut data).await;
        Ok(data)
    }
}

fn create_smb_negotiate_packet(flags1: u8, flags2: u16, nego_data: &[u8]) -> NewSMBPacket {
    let mut packet = NewSMBPacket::new(SMB_COM_NEGOTIATE, flags1, flags2);
    let negotiate_command = SMBCommand::new(SMB_COM_NEGOTIATE, Vec::new(), nego_data.to_vec());
    packet.add_command(negotiate_command);
    packet
}

pub async fn negotiate_session(server: &IpAddr, port: u16, timeout: Duration, extended_security: bool) -> crate::Result<Option<Vec<u8>>> {
    const FLAGS1_PATHCASELESS: u8 = 0x08;
    const FLAGS1_CANONICALIZED_PATHS: u8 = 0x10;
    const FLAGS2_EXTENDED_SECURITY: u16 = 0x0800;
    const FLAGS2_NT_STATUS: u16 = 0x4000;
    const FLAGS2_LONG_NAMES: u16 = 0x0001;
    const FLAGS2_UNICODE: u16 = 0x8000;

    let flags1 = FLAGS1_PATHCASELESS | FLAGS1_CANONICALIZED_PATHS;
    let mut flags2 = FLAGS2_NT_STATUS | FLAGS2_LONG_NAMES;

    if extended_security {
        flags2 |= FLAGS2_EXTENDED_SECURITY;
    }

    let nego_data = b"\x02NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00";

    for _ in 0..2 {
        match NetBIOSSessionService::connect((server.to_string(), port), timeout).await {
            Ok(mut nmb_session) => {
                let smbp = create_smb_negotiate_packet(flags1, flags2, nego_data);
                nmb_session.send_packet(&smbp.pack()).await?;

                match nmb_session.recv_packet().await {
                    Ok(resp) => return Ok(Some(resp)),
                    Err(e) => println!("Error receiving packet: {}", e),
                }
            }
            Err(e) => println!("Connection error: {}", e),
        }

        // Add more flags and try again
        flags2 |= FLAGS2_UNICODE;
    }

    Ok(None)
}

/*
fn main() -> std::io::Result<()> {
    let server = "139.182.180.178";
    let ports = [445, 445];
    let timeout = Duration::from_secs(30);

    for port in ports.iter() {
        println!("\nTrying to negotiate session on port {}", port);
        match negotiate_session(server, *port, timeout, true).await {
            Ok(Some(response)) => {
                println!("SMB Negotiate Response received:");
                println!("{:02X?}", response);
                return Ok(());
            }
            Ok(None) => println!("No valid SMB response received"),
            Err(e) => println!("Error during negotiation: {}", e),
        }
    }

    println!("\nFailed to establish an SMB connection with all attempted configurations.");
    Ok(())
}
*/
