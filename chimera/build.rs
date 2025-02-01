use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

fn main() {
    // Check if we're in CI environment (GitHub Actions sets this)
    let is_ci = env::var("CI").is_ok();
    
    // Check if APP_PASSWORD is set
    if let Ok(password) = env::var("APP_PASSWORD") {
        let password_path = Path::new(".password");
        
        // In CI, always use APP_PASSWORD
        // For local builds, only use APP_PASSWORD if .password doesn't exist
        if is_ci || !password_path.exists() {
            let mut file = File::create(password_path).unwrap();
            file.write_all(password.as_bytes()).unwrap();
            println!("cargo:warning=Using APP_PASSWORD for build");
        } else {
            println!("cargo:warning=Using existing .password file");
        }
    } else if !Path::new(".password").exists() {
        panic!("No .password file found and APP_PASSWORD not set");
    }
}
