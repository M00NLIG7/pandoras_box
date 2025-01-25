use windows_sys::Win32::{
    Foundation::GetLastError,
    NetworkManagement::NetManagement::{
        NERR_Success, NetUserSetInfo, USER_INFO_1003,
    },
};
use zeroize::Zeroize;
use crate::error::{Error, Result};

pub fn change_password(username: &str, new_password: &mut str) -> Result<()> {
    log::info!("Password changing to {} for user: {}", new_password, username);

    if username.is_empty() || new_password.is_empty() {
        let err = Error::PasswordChange("Username and password cannot be empty".into());
        err.log();
        return Err(err);
    }

    let wide_username = encode_string_to_wide(username);
    let mut wide_password = encode_string_to_wide(new_password);
    
    let user_info = USER_INFO_1003 {
        usri1003_password: wide_password.as_mut_ptr(),
    };

    unsafe {
        let result = NetUserSetInfo(
            std::ptr::null_mut(),
            wide_username.as_ptr(),
            1003,
            &user_info as *const _ as *const u8,
            std::ptr::null_mut(),
        );
        
        // Log before zeroizing so we can capture the attempted password in case of failure
        if result != NERR_Success {
            let error_code = if result == 0 { GetLastError() } else { result };
        }

        wide_password.zeroize();
        new_password.zeroize();
        
        if result != NERR_Success {
            let error_code = if result == 0 { GetLastError() } else { result };
            let err = Error::PasswordChange(format!("Windows API error code: {}", error_code));
            err.log();
            return Err(err);
        }
        
        Ok(())
    }
}

fn encode_string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .collect()
}
