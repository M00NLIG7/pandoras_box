use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let password_path = Path::new(".password");
    
    if let Ok(password) = env::var("APP_PASSWORD") {
        // Clean the password of whitespace and newlines
        let clean_password = password.trim().replace("\r", "").replace("\n", "");
        
        // Always use APP_PASSWORD if it's set, regardless of environment
        if password_path.exists() {
            println!("cargo:warning=Removing existing .password file");
            std::fs::remove_file(password_path).unwrap();
        }
        println!("cargo:warning=Creating new .password file from APP_PASSWORD");
        let mut file = File::create(password_path).unwrap();
        file.write_all(clean_password.as_bytes()).unwrap();
    } else if !password_path.exists() {
        panic!("No .password file found and APP_PASSWORD not set");
    } else {
        println!("cargo:warning=Using existing .password file");
    }
}
