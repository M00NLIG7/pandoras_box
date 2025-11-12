use sysinfo::{User, UserExt, SystemExt};
use crate::types::UserInfo;
use once_cell::sync::Lazy;

static LOCAL_DOMAIN_ID: Lazy<Option<String>> = Lazy::new(|| {
    // Get seperate list of users and filter for local admin
    let binding = sysinfo::System::new_all();
    let all_users = binding.users();

    // Extract domain id from local admin
    all_users
        .iter()
        .filter_map(|user| {
            let uid = &user.id().to_string();
            match get_rid_from_sid(uid) {
                Some(rid) if rid == "500" => match get_domain_id_from_sid(uid) {
                    Ok(domain_id) => Some(domain_id),
                    Err(_) => None,
                },
                _ => None,
            }
        })
        .next()
});

fn get_rid_from_sid(sid: &str) -> Option<&str> {
    sid.split('-').last()
}

fn get_domain_id_from_sid(sid: &str) -> Result<String, &'static str> {
    let parts: Vec<&str> = sid.split('-').collect();

    // Check if SID has the correct format
    if parts.len() < 8 || parts[0] != "S" {
        return Err("Invalid SID format");
    }

    // Extract the domain identifier parts
    let sub_authority1 = parts[4];
    let sub_authority2 = parts[5];
    let sub_authority3 = parts[6];

    // Combine the parts to form the domain identifier
    let domain_identifier = format!("{}-{}-{}", sub_authority1, sub_authority2, sub_authority3);

    Ok(domain_identifier)
}

impl UserInfo for sysinfo::User {
    fn is_admin(&self) -> bool {
        // Check for sudoers group in groups or uid 0 (root)
        self.groups().iter().any(|group| group == "Administrators") || self.id().to_string() == "0"
    }

    fn is_local(&self) -> bool {
        // Compare local domain id to domain ids of current user
        match get_domain_id_from_sid(&self.id().to_string()) {
            Ok(local_sid_value) => {
                // Check if LOCAL_DOMAIN_ID is available and matches
                match LOCAL_DOMAIN_ID.as_ref() {
                    Some(domain_id) => *domain_id == local_sid_value,
                    None => false, // If no local domain ID found, assume not local
                }
            }
            Err(_) => false,
        }
    }
}


