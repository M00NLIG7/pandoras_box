use num_cpus;
use sys_info;
// use std::convert::TryInto;

fn calculate_resource_weight(cpu_cores: u8, memory_mb: u64) -> u64 {
    let cpu_cores_weight = 4;
    let memory_weight = 2;

    (cpu_cores as u64 * cpu_cores_weight as u64 * 1024) + (memory_mb as u64 * memory_weight)
}

pub fn evil_fetch() {
    let cpu_cores: u8 = match num_cpus::get().try_into() {
        Ok(val) => val,
        Err(_) => {
            println!("Failed to get CPU core count");
            return;
        }
    };

    match sys_info::mem_info() {
        Ok(mem_info) => {
            let memory_mb: u64 = (mem_info.total / 1024).try_into().unwrap_or(0);
            let resource_weight = calculate_resource_weight(cpu_cores, memory_mb);
            println!("CPU Cores: {}", cpu_cores);
            println!("Memory: {} MB", memory_mb);
            println!("Resource Weight: {} units", resource_weight);
        }
        Err(e) => {
            println!("Failed to get memory info: {}", e);
        }
    }
}
