use std::io::{Write, Read, Result};
use std::process::Command;
use std::process::Stdio;

// fill_buffer fills the given buffer with as many bytes from the reader as possible. 
// It returns number of bytes read into the buffer (can be less than len(buffer)).
pub fn fill_buffer(reader: &mut impl Read, buffer: &mut Vec<u8>) -> Result<usize> {

    let bytes_read = reader.read(buffer)?;

    return Ok(bytes_read);
}
