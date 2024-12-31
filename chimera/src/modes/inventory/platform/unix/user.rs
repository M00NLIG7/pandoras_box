use sysinfo::{User, UserExt};
use crate::types::UserInfo;

impl UserInfo for User {
    // If compiled for linux
    fn is_admin(&self) -> bool {
        // Check for sudoers group in groups or uid 0 (root)
        self.groups().iter().any(|group| group == "wheel") || self.id().to_string() == "0"
    }

    fn is_local(&self) -> bool {
        true
    }

    // Reads from etc password and matches shell to the user
    fn shell(&self) -> String {
        todo!()
        // self.shell().into()
    }
}

