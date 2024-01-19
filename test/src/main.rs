use sysinfo::{System};

fn main() {
    let mut system = System::new_all();
    system.refresh_all();


    println!("Name : {:?}", System::name());

}
