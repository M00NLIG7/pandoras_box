// TODO
// Define the Communicator Trait:

// Ensure that your Communicator trait defines all necessary methods for communication, like execute_command.
// Implement Communicator for Different Protocols:

// Implement the Communicator trait for different protocols (e.g., SSHClient, WinexeClient).
// Create the CommunicatorPool Structure:

// Design the CommunicatorPool struct, deciding on the underlying data structure (e.g., Vec or HashMap).
// Implement Pool Management Functions:

// new: For creating a new pool.
// add_communicator: To add a new communicator to the pool.
// get_communicator: To retrieve a communicator for a specific IP.
// remove_communicator: To remove a communicator from the pool.
// Implement Connection Initialization:

// Establish connections when communicators are added to the pool.
// Implement Connection Health Checks:

// Periodically check the health of each connection and re-establish if necessary.
// Manage Connection Lifecycle:

// Implement logic for closing idle connections to free up resources.
// Implement Error Handling:

// Robust error handling for connection failures, command execution failures, etc.
// Concurrency and Thread Safety:

// Ensure that access to the pool and communicators is thread-safe, especially if using async code.
// Logging and Monitoring:

// Implement logging for important actions and errors for easier debugging and monitoring.
// Write Unit Tests:

// Create unit tests for your pool to ensure each functionality works as expected.
// Documentation:

// Document your code, especially public interfaces and methods, to make it clear how to use the pool and its communicators.
// Scalability Considerations:

// Plan for scalability, ensuring that the pool can handle an increasing number of communicators or higher loads efficiently.
// Security Measures:

// Implement security measures for managing connections and credentials, especially if dealing with sensitive data or remote execution.
// Optimization and Performance Testing:

// Profile and test the performance of your pool under different loads and use-cases to identify bottlenecks or optimization opportunities.
// Integrate with Main Application:

// Integrate the CommunicatorPool with your main application, ensuring it interacts correctly with other components.
// User-Friendly API:

// Design the pool's API to be user-friendly and intuitive, considering how developers will interact with it.

use crate::net::communicator::{Credentials, Session};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Represents a pool of Communicator instances.
pub struct SessionPool {
    sessions: Mutex<Vec<(String, Arc<Box<dyn Session>>)>>,
}

impl SessionPool {
    /// Creates a new CommunicatorPool.
    pub fn new() -> Self {
        SessionPool {
            sessions: Mutex::new(Vec::new()),
        }
    }

    /// Adds a Communicator to the pool.
    pub async fn add_session(&self, ip: String, session: Box<dyn Session>) {
        let mut sessions = self.sessions.lock().await;
        sessions.push((ip, Arc::new(session)));
    }

    /// Retrieves a Communicator for the given IP address.
    /// Returns None if no Communicator exists for the IP.
    pub async fn get_sessions(&self, ip: &str) -> Option<Arc<Box<dyn Session>>> {
        let sessions = self.sessions.lock().await;
        sessions
            .iter()
            .find(|(addr, _)| addr == ip)
            .map(|(_, comm)| Arc::clone(comm))
    }

    /// Removes the Communicator associated with the given IP.
    pub async fn remove_session(&self, ip: &str) {
        let mut sessions = self.sessions.lock().await;
        if let Some(index) = sessions.iter().position(|(addr, _)| addr == ip) {
            sessions.remove(index);
        }
    }
}
