use crate::error::{Error, Result};
use log::{debug, error, info, warn};
use windows_sys::Win32::{
    Foundation::GetLastError,
    NetworkManagement::NetManagement::{
        NERR_Success, NetApiBufferFree, NetServerGetInfo, NetUserSetInfo, SERVER_INFO_101,
        SV_TYPE_DOMAIN_CTRL, USER_INFO_1003,
    },
};
use zeroize::Zeroize;

fn is_domain_controller() -> Result<bool> {
    let mut server_info: *mut SERVER_INFO_101 = std::ptr::null_mut();

    unsafe {
        info!("Security Context Check: Starting NetServerGetInfo call");
        let mut server_info: *mut SERVER_INFO_101 = std::ptr::null_mut();

        // Log pre-call state
        info!(
            "Pre-call: server_info pointer is null: {}",
            server_info.is_null()
        );

        let result = NetServerGetInfo(
            std::ptr::null_mut(), // Local computer
            101,                  // Level for SERVER_INFO_101
            &mut server_info as *mut _ as *mut *mut u8,
        );

        info!("Post-call: NetServerGetInfo result code: {}", result);
        info!("Post-call: server_info is null: {}", server_info.is_null());

        if result == NERR_Success && !server_info.is_null() {
            let info = &*server_info;
            let is_dc = (info.sv101_type & SV_TYPE_DOMAIN_CTRL) != 0;

            // Log server info details
            info!("Server type value: 0x{:x}", info.sv101_type);
            info!(
                "DC bit check (SV_TYPE_DOMAIN_CTRL): 0x{:x}",
                SV_TYPE_DOMAIN_CTRL
            );
            info!(
                "Raw sv101_type & SV_TYPE_DOMAIN_CTRL: 0x{:x}",
                info.sv101_type & SV_TYPE_DOMAIN_CTRL
            );
            info!("Is DC calculation result: {}", is_dc);

            info!("Domain Controller Check: is_dc = {}", is_dc);
            NetApiBufferFree(server_info as *mut _);

            // Log post-free state
            info!("Post-free: server_info memory freed");
            Ok(is_dc)
        } else {
            let error_code = if result == 0 { GetLastError() } else { result };
            error!(
                "NetServerGetInfo failed - result: {}, GetLastError: {}",
                result, error_code
            );
            Err(Error::PasswordChange(format!(
                "Failed to check domain controller status: {}",
                error_code
            )))
        }
    }
}

pub fn change_password(username: &str, new_password: &mut str) -> Result<()> {
    info!("Attempting to change password for user: {}", username);

    if username.is_empty() || new_password.is_empty() {
        error!("Username or password is empty.");
        return Err(Error::PasswordChange(
            "Username and password cannot be empty".into(),
        ));
    }

    // Check if this is a domain controller
    let is_dc = match is_domain_controller() {
        Ok(is_dc) => {
            info!("Machine is{} a domain controller.", if is_dc { "" } else { " not" });
            if is_dc && username.eq_ignore_ascii_case("Administrator") {
                warn!("Cannot change Administrator password on a domain controller.");
                return Err(Error::PasswordChange(
                    "Cannot change Administrator password on a domain controller".into(),
                ));
            }
            is_dc
        }
        Err(e) => {
            error!("Error checking domain controller status: {:?}", e);
            return Err(e);
        }
    };

    info!("Proceeding with password change for user: {}", username);

    let wide_username = encode_string_to_wide(username);
    let mut wide_password = encode_string_to_wide(new_password);
    
    // Use NULL for domain operations, "." for local operations
    let wide_server = if is_dc {
        Vec::new() // Empty vec will result in null pointer
    } else {
        encode_string_to_wide(r".")
    };

    let user_info = USER_INFO_1003 {
        usri1003_password: wide_password.as_mut_ptr(),
    };

    unsafe {
        info!("Calling NetUserSetInfo to change {} password.", 
            if is_dc { "domain" } else { "local" });
            
        let result = NetUserSetInfo(
            if is_dc { std::ptr::null_mut() } else { wide_server.as_ptr() },
            wide_username.as_ptr(),
            1003,
            &user_info as *const _ as *const u8,
            std::ptr::null_mut(),
        );

        // Securely clear sensitive data
        wide_password.zeroize();
        new_password.zeroize();

        if result != NERR_Success {
            let error_code = if result == 0 { GetLastError() } else { result };
            error!("NetUserSetInfo failed with error code: {}", error_code);
            return Err(Error::PasswordChange(format!(
                "Windows API error code: {}",
                error_code
            )));
        }

        info!("{} password changed successfully for user: {}", 
            if is_dc { "Domain" } else { "Local" },
            username
        );
        Ok(())
    }
}

fn encode_string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16()
        .chain(std::iter::once(0)) // Null-terminate
        .collect()
}
