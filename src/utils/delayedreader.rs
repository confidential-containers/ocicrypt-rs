use std::io::{Error, ErrorKind, Read, Result};
use crate::ioutils::fill_buffer;
use std::convert::From;

fn min(a: usize, b: usize) -> usize {
    if a < b {
        return a;
    }

    return b;
}
