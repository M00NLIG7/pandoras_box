use crate::Result;
use std::path::PathBuf;
use std::sync::Arc;

/// Trait defining what a Session is.
/// A session is a connection to the server.
/// It can be used to execute commands and listen for lifecycle events.
/// It can be killed by a Client
pub trait Session {
    fn disconnect(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
    fn exec(
        &self,
        cmd: &Command,
    ) -> impl std::future::Future<Output = Result<CommandOutput>> + Send;
    fn download_file(
        &self,
        remote_path: &str,
        local_path: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn transfer_file(
        &self,
        file: Arc<Vec<u8>>,
        destination: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Trait defining the configuration for a client.
pub trait Config {
    #[allow(private_bounds)]
    type SessionType: Session;

    fn create_session(&self)
        -> impl std::future::Future<Output = Result<Self::SessionType>> + Send;
}

/// Represents the output of a command execution.
#[derive(Debug)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status_code: Option<u32>,
}
/*
let command_str: String = cmd.into();
    |                                       ^^^^ the trait `From<&client::Command>` is not implemented for `std::string::String`, which is required by `&client::Command: Into<_>`

*/

/// Enum representing the connection state.
pub enum ConnectionState {
    Connected,
    Disconnected,
    Error(crate::Error),
}

/// Struct representing a command that can be executed on the server.
#[derive(Clone, Debug)]
pub struct Command {
    pub cmd: String,
    pub args: Vec<String>,
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cmd)?;
        for arg in &self.args {
            write!(f, " {}", arg)?;
        }
        Ok(())
    }
}

impl From<Command> for String {
    fn from(command: Command) -> Self {
        std::iter::once(command.cmd.as_str()) // Convert the command into a byte slice wrapped in an iterator
            .chain(command.args.iter().flat_map(
                |arg| // For each arg, create an iterator of the space and the arg bytes
                std::iter::once(" ").chain(std::iter::once(arg.as_str())),
            ))
            .collect::<Vec<&str>>()
            .join("")
    }
}

impl From<&Command> for String {
    fn from(command: &Command) -> Self {
        std::iter::once(command.cmd.as_str()) // Convert the command into a byte slice wrapped in an iterator
            .chain(command.args.iter().flat_map(
                |arg| // For each arg, create an iterator of the space and the arg bytes
                std::iter::once(" ").chain(std::iter::once(arg.as_str())),
            ))
            .collect::<Vec<&str>>()
            .join("")
    }
}

impl From<Command> for Vec<u8> {
    fn from(command: Command) -> Self {
        std::iter::once(command.cmd.as_bytes()) // Convert the command into a byte slice wrapped in an iterator
            .chain(command.args.iter().flat_map(
                |arg| // For each arg, create an iterator of the space and the arg bytes
                std::iter::once(&b" "[..]).chain(std::iter::once(arg.as_bytes())),
            ))
            .flatten() // Flatten the iterator of iterators into a single iterator of bytes
            .copied() // Copy the bytes (since we have &u8 from slices, not u8)
            .collect() // Collect into Vec<u8>
    }
}

impl From<&Command> for Vec<u8> {
    fn from(command: &Command) -> Self {
        std::iter::once(command.cmd.as_bytes()) // Convert the command into a byte slice wrapped in an iterator
            .chain(command.args.iter().flat_map(
                |arg| // For each arg, create an iterator of the space and the arg bytes
                std::iter::once(&b" "[..]).chain(std::iter::once(arg.as_bytes())),
            ))
            .flatten() // Flatten the iterator of iterators into a single iterator of bytes
            .copied() // Copy the bytes (since we have &u8 from slices, not u8)
            .collect() // Collect into Vec<u8>
    }
}

/// Implementation of the `Command` struct.
impl Command {
    /// Creates a new `Command` instance with the specified command.
    pub fn new<S: Into<String>>(cmd: S) -> Self {
        Command {
            cmd: cmd.into(),
            args: Vec::new(),
        }
    }

    /// Adds an argument to the command. This method takes any type that can be converted into a `String`.
    /// and returns a `Command` instance.
    pub fn arg<S: Into<String>>(mut self, arg: S) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds multiple arguments to the command. This method takes an iterator of types that can be converted into a `String`.
    /// and returns a `Command` instance.
    pub fn args<S: Into<String>, I: IntoIterator<Item = S>>(mut self, args: I) -> Self {
        self.args.extend(args.into_iter().map(|s| s.into()));
        self
    }

    /// Returns the command string.
    pub fn get_cmd(&self) -> &str {
        &self.cmd
    }

    /// Returns the arguments as a vector of strings.
    pub fn get_args(&self) -> &Vec<String> {
        &self.args
    }
}

/// Trait defining the operations that a client can perform.
/// A client can connect, disconnect, and execute commands.
/// The client can also listen for lifecycle events.
#[allow(unused)]
pub struct Client<T: Config> {
    session: T::SessionType,
}

/// Example usage:
/// ```rust
/// use rustrc::{
///    client::Client,
///   ssh::SSHConfig,
///   winexe::WinexeConfig,
///    cmd,
///    };
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> rustrc::Result<()> {
///     /*
///    let config = SSHConfig::password("root", "192.168.1.1:22", "password", Duration::from_secs(30)).await?;
///    let mut client = Client::connect(config).await?;
///
///    let output = client.exec(cmd!("ls", "-la")).await?;
///
///    println!("stdout: {:?}", output.stdout);
///
///    client.disconnect().await?;
///    */
///
///    Ok(())
/// }
/// ```
#[allow(unused)]
impl<T: Config> Client<T> {
    pub async fn connect(config: T) -> Result<Self> {
        let session = config.create_session().await?;
        Ok(Client { session })
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.session.disconnect().await
    }

    pub async fn exec(&self, cmd: &Command) -> Result<CommandOutput> {
        self.session.exec(cmd).await
    }

    pub async fn transfer_file(&self, file_data: Arc<Vec<u8>>, remote_dest: &str) -> Result<()> {
        self.session.transfer_file(file_data, remote_dest).await
    }

    pub async fn download_file(&self, remote_path: &str, local_path: &str) -> Result<()> {
        self.session.download_file(remote_path, local_path).await
    }
}
