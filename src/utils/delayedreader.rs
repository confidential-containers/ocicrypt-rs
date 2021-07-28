use std::io::{Error, ErrorKind, Read, Result};
use crate::ioutils::fill_buffer;
use std::convert::From;

fn min(a: usize, b: usize) -> usize {
    if a < b {
        return a;
    }

    return b;
}

struct DelayedReader {
    reader: Box<dyn Read>,
    err : Option<ErrorKind>,
    buffer : Vec<u8>,
    bufbytes : usize,
    bufoff : usize,
    is_eof : bool,
}