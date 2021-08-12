
use super::delayedreader::{new_delayed_reader};
use std::io::{BufReader, Read};

fn make_range_exp(n: usize) -> Vec<usize> {
    let mut vec: Vec<usize> = Vec::new();
    let mut step: usize = 1;
    for _ in 1..n {
        vec.push(step);
        step *= 2;
    }
    vec
}

fn make_range(from: usize, to: usize) -> Vec<usize> {
    let mut vec: Vec<usize> = Vec::new();
    for i in from..to {
        vec.push(i);
    }
    vec
}

fn equal_slices(s1: &[u8], s2: &[u8]) -> bool {
    if s1.len() != s2.len(){
        return false;
    }

    for i in 1..s1.len() {
        if s1[i] != s2[i] {
            return false;
        }
    }

    return true;
}

static EXP_RANGE_VAL: usize = 20;
static RANGE_FROM_VAL: usize = 2;
static RANGE_TO_VAL: usize = 32;

#[test]
fn test_delayed_reader() {
    let mut buf: Vec<u8> = Vec::with_capacity(10);

    for buf_len in make_range_exp(EXP_RANGE_VAL) {
        let obuf: Vec<u8> = Vec::with_capacity(buf_len);

        for buf_size in make_range(RANGE_FROM_VAL, RANGE_TO_VAL) {
            let reader = BufReader::new(&obuf[..]);
            let mut dr = new_delayed_reader(reader, buf_size);

            let mut ibuf: Vec<u8> = Vec::new();
            loop {
                let n = match dr.read(&mut buf) {
                    Ok(n) => n,
                    Err(_) => panic!(),
                };
                // assert_ne!(n, 0);

                ibuf.extend_from_slice(&buf[..n]);
                if n == 0 { /* EOF */ 
                    break;
                }
            }
            
            assert!(equal_slices(&ibuf, &obuf));
        }
    }
}