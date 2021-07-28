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

pub fn new_delayed_reader(reader: Box<dyn Read>, buffer_size: usize) -> impl Read {
    DelayedReader {
        reader: reader,
        buffer: vec![0; buffer_size],
        err: None,
        bufbytes: 0,
        bufoff: 0,
        is_eof: false,
    }
}