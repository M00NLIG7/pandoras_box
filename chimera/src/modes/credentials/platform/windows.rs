use windows_sys::Win32::{
    Foundation::GetLastError,
    NetworkManagement::NetManagement::{
        NERR_Success, NetUserSetInfo, USER_INFO_1003,
        NetServerGetInfo, SERVER_INFO_101, SV_TYPE_DOMAIN_CTRL,
        NetApiBufferFree,
    },
};
use zeroize::Zeroize;
use crate::error::{Error, Result};
use log::{info, error, debug, warn};

fn is_domain_controller() -> Result<bool> {
    let mut server_info: *mut SERVER_INFO_101 = std::ptr::null_mut();
    
    unsafe {
        info!("Calling NetServerGetInfo to check domain controller status.");
        let result = NetServerGetInfo(
            std::ptr::null_mut(), // Local computer
            101,                  // Level for SERVER_INFO_101
            &mut server_info as *mut _ as *mut *mut u8,
        );
        
        if result == NERR_Success && !server_info.is_null() {
            let info = &*server_info; // Safe to dereference
            let is_dc = (info.sv101_type & SV_TYPE_DOMAIN_CTRL) != 0;
            info!("Domain Controller Check: is_dc = {}", is_dc);
            NetApiBufferFree(server_info as *mut _); // Free memory
            Ok(is_dc)
        } else {
            let error_code = if result == 0 { GetLastError() } else { result };
            error!("NetServerGetInfo failed with error code: {}", error_code);
            Err(Error::PasswordChange(format!("Failed to check domain controller status: {}", error_code)))
        }
    }
}

pub fn change_password(username: &str, new_password: &mut str) -> Result<()> {
    info!("Attempting to change password for user: {}", username);

    if username.is_empty() || new_password.is_empty() {
        error!("Username or password is empty.");
        return Err(Error::PasswordChange("Username and password cannot be empty".into()));
    }

    // Check if this is a domain controller
    match is_domain_controller() {
        Ok(true) => {
            info!("Machine is a domain controller.");
            if username.eq_ignore_ascii_case("Administrator") {
                warn!("Cannot change Administrator password on a domain controller.");
                return Err(Error::PasswordChange("Cannot change Administrator password on a domain controller".into()));
            }
        }
        Ok(false) => {
            info!("Machine is not a domain controller.");
        }
        Err(e) => {
            error!("Error checking domain controller status: {:?}", e);
            return Err(e);
        }
    }

    info!("Proceeding with password change for user: {}", username);

    let wide_username = encode_string_to_wide(username);
    let mut wide_password = encode_string_to_wide(new_password);
    
    let user_info = USER_INFO_1003 {
        usri1003_password: wide_password.as_mut_ptr(),
    };

    unsafe {
        info!("Calling NetUserSetInfo to change password.");
        let result = NetUserSetInfo(
            std::ptr::null_mut(),  // NULL means local computer
            wide_username.as_ptr(),
            1003,
            &user_info as *const _ as *const u8,
            std::ptr::null_mut(),
        );
        
        wide_password.zeroize();
        new_password.zeroize();
        
        if result != NERR_Success {
            let error_code = if result == 0 { GetLastError() } else { result };
            error!("NetUserSetInfo failed with error code: {}", error_code);
            return Err(Error::PasswordChange(format!("Windows API error code: {}", error_code)));
        }
        
        info!("Password changed successfully for user: {}", username);
        Ok(())
    }
}

fn encode_string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16()
        .chain(std::iter::once(0)) // Null-terminate
        .collect()
}
