use std::io::{Write, Read, Result};
use std::process::Command;
use std::process::Stdio;

// fill_buffer fills the given buffer with as many bytes from the reader as possible. 
// It returns number of bytes read into the buffer (can be less than len(buffer)).
pub fn fill_buffer(reader: &mut impl Read, buffer: &mut Vec<u8>) -> Result<usize> {

    let bytes_read = reader.read(buffer)?;

    return Ok(bytes_read);
}

pub struct Runner {}

pub trait CommandExecuter {
    fn exec(&self, cmd_name: &str, args: &Vec<&str>, input: &mut Vec<u8>) -> Result<Vec<u8>>;
}

impl CommandExecuter for Runner {
    fn exec(&self, cmd_name: &str, args: &Vec<&str>, input: &mut Vec<u8>) -> Result<Vec<u8>>{
        
        let mut child = Command::new(cmd_name)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        let mut stdin = child.stdin.take().expect("Failed to open stdin");
        
        let mut input_copy = input.to_vec();

        std::thread::spawn(move || {            
                stdin.write_all(input_copy.as_mut_slice()).expect("Failed to write to stdin");
        });

        let output = child.wait_with_output().expect("Failed to read stdout");

        Ok(output.stdout)
    }
}