extern crate clap;
extern crate md5;
extern crate rand;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use rand::prelude::*;

use std::error::Error;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::process;

use my_des::*;

const BUFFER_SIZE: usize = 1024 * 64;

// Iterator for reading the input file in chunks.
struct ChunkReader {
    action: des::Action,
    file: fs::File,
    buffer_size: usize,
    done: bool,
}

// Each iteration will read one chunk of the file. We need to know if
// the current chunk is the last one, in case we have to add or remove
// the padding.
struct Chunk {
    data: Vec<u64>,
    is_last_chunk: bool,
}

impl ChunkReader {
    fn new(action: des::Action, file_name: &str) -> Result<ChunkReader, io::Error> {
        let f = fs::File::open(file_name)?;
        Ok(ChunkReader {
            action: action,
            file: f,
            // Since we read bytes from the file, but want to have 64
            // bit blocks, the actual buffer size must (!) be a
            // multiple of 8 so that we always have complete blocks.
            buffer_size: BUFFER_SIZE * 8,
            done: false,
        })
    }
}

impl Iterator for ChunkReader {
    type Item = Result<Chunk, io::Error>;

    // Read BUFFER_SIZE 64 bit blocks from the file, add padding to
    // the last block if necessary, and return a vector of u64.
    fn next(&mut self) -> Option<Self::Item> {
        if !self.done {
            let mut raw_buffer: Vec<u8> = vec![0u8; self.buffer_size];
            let bytes_read = match self.file.read(&mut raw_buffer) {
                Err(e) => {
                    return Some(Err(e));
                }
                Ok(b) => b,
            };

            self.done = !(bytes_read == self.buffer_size);
            let pad: bool = self.action == des::Action::Encrypt && self.done;
            let buffer: Vec<u64> = prepare_input(&raw_buffer[0..bytes_read].to_vec(), pad);

            return Some(Ok(Chunk {
                data: buffer,
                is_last_chunk: self.done,
            }));
        }
        return None;
    }
}

struct ChunkWriter {
    action: des::Action,
    out_file: fs::File,
}

impl ChunkWriter {
    pub fn new(action: des::Action, out_file_name: &str) -> Result<ChunkWriter, io::Error> {
        let out_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out_file_name)?;

        Ok(ChunkWriter {
            action: action,
            out_file: out_file,
        })
    }

    pub fn write(&mut self, data: &Vec<u64>, is_last_chunk: bool) -> Result<(), io::Error> {
        let remove_padding: bool = self.action == des::Action::Decrypt && is_last_chunk;
        let output: Vec<u8> = prepare_output(data, remove_padding);
        return self.out_file.write_all(&output);
    }
}

// Convert read bytes to a Vector of 64-bit values, optionally
// including ANSI X9.23 padding (for the encryption case).
fn prepare_input(data: &Vec<u8>, add_padding: bool) -> Vec<u64> {
    let num_pad_bytes = match add_padding {
        true => 8 - (data.len() % 8),
        false => 0,
    };
    let mut result: Vec<u64> = Vec::with_capacity((data.len() / 8) + 8);
    let mut buf: u64 = 0;

    let mut rng = rand::thread_rng();
    for i in 0..(data.len() + num_pad_bytes) {
        buf <<= 8;
        if i < data.len() {
            buf |= data[i] as u64;
        } else if i == data.len() + num_pad_bytes - 1 {
            buf |= num_pad_bytes as u64;
        } else {
            buf |= rng.gen_range(0, 255);
        }

        if i % 8 == 7 {
            result.push(buf);
            buf = 0;
        }
    }

    return result;
}

// Convert encrypted or decrypted 64-bit blocks back to a Vector of u8
// values, optionally removing the ANSI X9.23 padding (for the
// decryption case).
fn prepare_output(data: &Vec<u64>, remove_padding: bool) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(data.len() * 8);
    for &n in data.iter() {
        for i in (0..8).rev() {
            let t: u8 = ((n & (0xFF << (i * 8))) >> (i * 8)) as u8;
            result.push(t);
        }
    }

    if remove_padding && result.len() > 0 {
        let pad_bytes = result.pop().unwrap();
        for _ in 1..pad_bytes {
            result.pop();
        }
    }

    return result;
}

// Read the key file, and derive a 64-bit key by using half of the
// bits from the MD5 digest.
fn read_key(args: &ArgMatches) -> Result<u64, io::Error> {
    let mut result: u64 = 0;

    let key = fs::read_to_string(args.value_of("key").unwrap())?;
    let digest = md5::compute(key);

    for i in 8..16 {
        result <<= 8;
        result |= digest.0[i] as u64;
    }

    return Ok(result);
}

// Get the corresponding cipher mode.
fn get_cipher_mode(args: &ArgMatches) -> Box<dyn Cipher> {
    let mode: Box<dyn Cipher> = match args.value_of("mode").unwrap() {
        "ECB" => Box::new(my_des::ECB::new()),
        "CBC" => Box::new(my_des::CBC::new()),
        _ => panic!("Unknown cipher mode!"),
    };
    return mode;
}

// Encrypt or decrypt according to arguments.
fn run(
    action: des::Action,
    args: &ArgMatches,
    f: &dyn Fn(Vec<u64>, u64, &mut Box<dyn Cipher>) -> Vec<u64>,
) -> Result<(), io::Error> {
    let key: u64 = match read_key(&args) {
        Err(e) => {
            eprintln!("Error getting the key: {}", e);
            return Err(e);
        }
        Ok(k) => k,
    };

    let mut mode = get_cipher_mode(args);

    let reader = match ChunkReader::new(action, args.value_of("in").unwrap()) {
        Err(e) => {
            eprintln!("Error while trying to open input file: {}", e);
            return Err(e);
        }
        Ok(r) => r,
    };
    let mut writer = match ChunkWriter::new(action, args.value_of("out").unwrap()) {
        Err(e) => {
            eprintln!("Error while trying to open output file: {}", e);
            return Err(e);
        }
        Ok(w) => w,
    };

    for chunk in reader {
        let (processed, is_last_chunk) = match chunk {
            Err(e) => {
                eprintln!("Error while reading the input file: {}", e);
                return Err(e);
            }
            Ok(chunk) => (f(chunk.data, key, &mut mode), chunk.is_last_chunk),
        };

        match writer.write(&processed, is_last_chunk) {
            Err(e) => {
                eprintln!("Could not write to output file: {}", e);
                return Err(e);
            }
            Ok(_) => {}
        }
    }

    return Ok(());
}

// Encrypt according to arguments.
fn encrypt(args: &ArgMatches) -> Result<(), io::Error> {
    return run(des::Action::Encrypt, args, &my_des::encrypt);
}

// Decrypt according to arguments.
fn decrypt(args: &ArgMatches) -> Result<(), io::Error> {
    return run(des::Action::Decrypt, args, &my_des::decrypt);
}

fn main() -> Result<(), Box<dyn Error>> {
    let modes = ["ECB", "CBC"];

    let matches = App::new("my_des")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("encrypt"))
        .subcommand(SubCommand::with_name("decrypt"))
        .arg(
            Arg::with_name("mode")
                .short("m")
                .long("mode")
                .required(true)
                .takes_value(true)
                .possible_values(&modes)
                .help("ECB or CBC"),
        )
        .arg(
            Arg::with_name("in")
                .short("i")
                .long("in")
                .required(true)
                .takes_value(true)
                .help("Input file"),
        )
        .arg(
            Arg::with_name("out")
                .short("o")
                .long("out")
                .required(true)
                .takes_value(true)
                .help("Output file"),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .required(true)
                .takes_value(true)
                .help("Key file"),
        )
        .get_matches();

    let result = match matches.subcommand() {
        ("encrypt", Some(_)) => encrypt(&matches),
        ("decrypt", Some(_)) => decrypt(&matches),
        _ => panic!("Action should be encrypt or decrypt!"),
    };

    match result {
        Err(_) => {
            eprintln!("Something went wrong!");
            process::exit(1);
        }
        Ok(_) => {
            println!("Success!");
            return Ok(());
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_input_output_preparation_with_padding() {
        let mut rng = rand::thread_rng();

        for _ in 0..256 {
            let mut data: Vec<u8> = Vec::new();
            let data_size = rng.gen_range(0, 1024);
            for _ in 0..data_size {
                data.push(rng.gen_range(0, 255));
            }

            let blocks: Vec<u64> = prepare_input(&data, true);
            let bytes: Vec<u8> = prepare_output(&blocks, true);
            assert_eq!(data, bytes);
        }
    }

    #[test]
    fn test_input_output_preparation_without_padding() {
        let mut rng = rand::thread_rng();

        for _ in 0..256 {
            let mut data: Vec<u8> = Vec::new();
            let data_size = rng.gen_range(0, 16);
            for _ in 0..(data_size * 64) {
                data.push(rng.gen_range(0, 255));
            }

            let blocks: Vec<u64> = prepare_input(&data, false);
            let bytes: Vec<u8> = prepare_output(&blocks, false);
            assert_eq!(data, bytes);
        }
    }
}
