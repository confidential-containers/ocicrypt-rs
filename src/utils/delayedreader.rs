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

impl Read for DelayedReader {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {

        if !self.err.is_none() {
            return Err(Error::from(self.err.unwrap()));
        }

        // if we are completely drained, return io.EOF
        if  self.is_eof {
            return Ok(0);
        }       

        let mut read_more: bool = true;

        // only at the beginning we fill our delay buffer in an extra step
        if self.bufbytes < self.buffer.len() {

            match fill_buffer(&mut self.reader, &mut self.buffer) {
                Ok(bytes_read) => {
                    self.bufbytes = bytes_read;
                    read_more = bytes_read == self.buffer.len();
                },
                Err(r) => {
                    self.err = Some(r.kind());
                    return Err(r);
                }
            };
        }

        let mut temp_buf: Vec<u8> = Vec::new();
        let mut temp_buff_bytes: usize = 0;
        if read_more {
            temp_buf.resize(buf.len(), 0);
            
            match fill_buffer(&mut self.reader, &mut temp_buf) {
                Ok(bytes_read) => {
                    temp_buff_bytes = bytes_read;
                },
                Err(r) => {
                    self.err = Some(r.kind());
                    return Err(r);
                }
            };
        }

        // copy out of the delay buffer into buff
        let to_copy1 = min(buf.len(), self.bufbytes);
        let c1: usize = to_copy1; 
        {
            let buffoff_end: usize = self.bufoff + c1;

            let (left_slice, _) = buf.split_at_mut(to_copy1);
            left_slice.copy_from_slice(&self.buffer[self.bufoff..buffoff_end]);
        }

        self.bufoff += c1;
        self.bufbytes -= c1;

        let mut c2: usize = 0;
        if c1 < buf.len() {
            // copy out of the temp_buf into buf            
            {
                let (_, right_slice) = buf.split_at_mut(to_copy1);

                c2 = min(right_slice.len(), temp_buff_bytes);

                let (final_slice, _) = right_slice.split_at_mut(c2);
                final_slice.copy_from_slice(&temp_buf[..c2]);                                
            }            
        }

        // if temp_buf holds data we need to hold onto, copy them
        // into the delay buffer    
        if temp_buff_bytes - c2 > 0 {
            // left-shift the delay buffer and append the temp_buf's remaining data
            let buffoff_end: usize = self.bufoff + self.bufbytes;

            let slice = &self.buffer[self.bufoff..buffoff_end];
            self.buffer = slice.to_vec();
            self.buffer.extend_from_slice(&temp_buf[c2..temp_buff_bytes]);
            self.bufoff = 0;
            self.bufbytes = self.buffer.len();
        }

        if self.bufbytes == 0 {
            self.is_eof = true;
        }

        return Ok(c1 + c2);
    }
}