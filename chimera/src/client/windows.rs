use sysinfo::UserExt;

impl super::client::UserInfo for sysinfo::User {
    fn is_admin(&self) -> bool {
        // Check for sudoers group in groups or uid 0 (root)
        self.groups().iter().any(|group| group == "Administrators") || self.id().to_string() == "0"
    }

    fn is_local(&self) -> bool {
        let local_user_sid_pattern = regex::Regex::new(r"S-1-5-21-\d{2,}-1000-\d+").unwrap();

        // Check if user is local based on SID
        // self.id().to_string() == "S-1-5-21-1004336348-1177238915-682003330-513"
        local_user_sid_pattern.is_match(&self.id().to_string())
    }
}
