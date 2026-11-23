use crate::types::UserInfo;
use sysinfo::{User, UserExt};

impl UserInfo for User {
    fn is_admin(&self) -> bool {
        // Check for sudoers group in groups or uid 0 (root)
        self.groups().iter().any(|group| group == "wheel") || self.id().to_string() == "0"
    }

    fn is_local(&self) -> bool {
        true
    }
}
