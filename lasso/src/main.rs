use nix::mount::{mount, umount2, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::Mode;
use nix::unistd::{chdir, chroot, mkdir, pivot_root};
use std::path::Path;
use std::process::Command;
use std::{io, io::Write};

fn main() -> nix::Result<()> {
    // Creating a new UTS namespace
    // unshare(CloneFlags::CLONE_NEWUTS)?;
    unshare(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWNET
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWCGROUP
            | CloneFlags::CLONE_FILES,
    )?;

    // Set up overlay filesystem
    let lower_dir = Path::new("/tmp/img/rootfs");
    let overlay_path = Path::new("/tmp/overlay");
    let upper_dir = Path::new("/tmp/overlay/upper");
    let work_dir = Path::new("/tmp/overlay/work");
    let overlay_mount = Path::new("/tmp/overlay/mount");

    mkdir(overlay_path, Mode::S_IRWXU)?;
    mkdir(upper_dir, Mode::S_IRWXU)?;
    mkdir(work_dir, Mode::S_IRWXU)?;
    mkdir(overlay_mount, Mode::S_IRWXU)?;
    println!("created mount dir");

    println!("mounting overlay");
    let options = &format!(
        "lowerdir={},upperdir={},workdir={}",
        lower_dir.display(),
        upper_dir.display(),
        work_dir.display()
    );

    print!("mounting overlay: {}", options);
    mount(
        Some("overlay"),
        overlay_mount,
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )?;

    println!("mounted");

    // chroot(overlay_mount)?;
    // chdir("/")?;

    // for entry in read_dir("/").unwrap() {
    //     let entry = entry.unwrap();
    //     println!("entry: {:?}", entry);
    // }

    // Now the process is in a new UTS namespace
    // You can change the hostname in this namespace without affecting the global hostname
    // println!("{:?}", split_paths(unparsed));

    // loop {
    //     // Print the prompt
    //     print!("> ");
    //     io::stdout().flush().unwrap();

    //     // Read a line of input
    //     let mut input = String::new();
    //     io::stdin().read_line(&mut input).unwrap();

    //     // Remove the newline character
    //     let input = input.trim();

    //     // Exit the shell on 'exit' command
    //     if input == "exit" {
    //         break;
    //     }

    //     // Execute the command
    //     let output = Command::new("sh")
    //         .arg("-c")
    //         .arg(input)
    //         .output()
    //         .expect("Failed to execute command");

    //     // Print the output
    //     io::stdout().write_all(&output.stdout).unwrap();
    //     io::stderr().write_all(&output.stderr).unwrap();
    // }

    umount2(overlay_mount, nix::mount::MntFlags::MNT_DETACH)?;
    Ok(())
}
