use shrs::prelude::{Env, ShellBuilder};

use crossterm::{
    event::{read, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::BufRead;
use std::io::{self, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

fn main() {
    let x = false;

    // Create a channel for sending data to the runc process
    let (tx, rx) = mpsc::channel::<String>();

    // Spawn the runc process in a new thread
    thread::spawn(move || {
        let mut child = Command::new("runc")
            .arg("run")
            .arg("-b")
            .arg("/usr/local/bin/jail")
            .arg("jail")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start runc");

        let mut child_stdin = child.stdin.take().expect("Failed to open stdin");
        let child_stdout = child.stdout.take().unwrap();
        let child_stderr = child.stderr.take().unwrap();

        // Handling stdout and stderr in separate threads
        let stdout_handle = thread::spawn(move || {
            let reader = BufReader::new(child_stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        if line.trim().is_empty() || line.contains("#") {
                            continue;
                        }
                        println!("{}", line);
                    }
                    Err(e) => {
                        eprintln!("Error reading stdout: {}", e);
                        break;
                    }
                }
            }
        });

        let stderr_handle = thread::spawn(move || {
            let reader = BufReader::new(child_stderr);
            for line in reader.lines() {
                eprintln!("{}", line.unwrap());
            }
        });

        // Write data to the child's stdin as it arrives
        for command in rx {
            writeln!(child_stdin, "{}", command).expect("Failed to write to stdin");
        }

        // Wait for the child process to exit
        child.wait().expect("Failed to wait on child");

        // Ensure stdout and stderr handles are finished
        stdout_handle.join().expect("Failed to join stdout handle");
        stderr_handle.join().expect("Failed to join stderr handle");
    });

    // Setup terminal in raw mode
    enable_raw_mode().expect("Failed to enable raw mode");
    execute!(io::stdout(), EnterAlternateScreen).expect("Failed to enter alternate screen");

    let mut command = String::new();

    // Print the initial prompt
    print_prompt();

    loop {
        match read().expect("Failed to read event") {
            Event::Key(key_event) => {
                match key_event.code {
                    KeyCode::Char(c) => {
                        print!("{}", c);
                        io::stdout().flush().unwrap();
                        command.push(c);
                    }
                    KeyCode::Backspace => {
                        if !command.is_empty() {
                            command.pop();
                            // Move cursor back, replace with space and move back again
                            print!("\x08 \x08");
                            io::stdout().flush().unwrap();
                        }
                    }
                    KeyCode::Enter => {
                        println!();
                        if !command.is_empty() {
                            tx.send(command.clone()).expect("Failed to send command");

                            // Check if the command is 'exit'
                            if command.trim() == "exit" {
                                break; // Break out of the loop to end the program
                            }

                            command.clear();
                        }
                        // Wait 100 ms
                        std::thread::sleep(std::time::Duration::from_millis(100));

                        // Print the prompt immediately after handling the command
                        print_prompt();
                    }
                    KeyCode::Esc => {
                        break;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    // Cleanup
    execute!(io::stdout(), LeaveAlternateScreen).expect("Failed to leave alternate screen");
    disable_raw_mode().expect("Failed to disable raw mode");

    let mut env = Env::new();
    env.load();

    let shell = ShellBuilder::default().with_env(env).build().unwrap();

    shell.run();


}

fn print_prompt() {
    print!("$ ");
    io::stdout().flush().unwrap();
}
