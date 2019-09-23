extern crate clap;
extern crate md5;
extern crate rand;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use rand::prelude::*;

use std::error::Error;
use std::fs;
use std::io::{Read, Write};

use my_des::*;


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
            buf |= num_pad_bytes as u64
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

    if remove_padding {
        // TODO: handle possible error case where data is empty.
        let pad_bytes = result.pop().unwrap();
        for _ in 1..pad_bytes {
            result.pop();
        }
    }

    return result;
}

// Read the input file.
fn read_input(args: &ArgMatches, add_padding: bool) -> Vec<u64> {
    // TODO: error handling...
    let mut in_file = fs::File::open(args.value_of("in").unwrap()).unwrap();
    let mut data: Vec<u8> = Vec::new();
    let _data_bytes_read = in_file.read_to_end(&mut data).unwrap();
    let input = prepare_input(&data, add_padding);
    return input;
}

// Read the key file, and derive a 64-bit key by using half of the
// bits from the MD5 digest.
fn read_key(args: &ArgMatches) -> u64 {
    // TODO: error handling...
    let mut result: u64 = 0;

    let key = fs::read_to_string(args.value_of("key").unwrap()).unwrap();
    let digest = md5::compute(key);

    for i in 8..16 {
        result <<= 8;
        result |= digest.0[i] as u64;
    }

    return result;
}

// Get the corresponding cipher mode.
fn get_cipher_mode(args: &ArgMatches) -> Box<dyn Cipher> {
    let mode: Box<dyn Cipher> = match args.value_of("mode").unwrap() {
        "ECB" => Box::new(my_des::ECB),
        "CBC" => Box::new(my_des::CBC),
        _ => panic!("Unknown cipher mode!"),
    };
    return mode;
}

// Write the output file.
fn write_output(args: &ArgMatches, output: &Vec<u64>, remove_padding: bool) -> std::io::Result<()> {
    // TODO: error handling...
    let mut out_file = match fs::OpenOptions::new().write(true)
        .create_new(true)
        .open(args.value_of("out").unwrap()) {
            Err(e) => { panic!(e) },
            Ok(f) => f,
        };

    let to_file: Vec<u8> = prepare_output(output, remove_padding);
    let success = out_file.write_all(&to_file);
    return success;
}

// Encrypt according to arguments.
fn encrypt(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    // TODO: actual error handling...
    let input = read_input(args, true);
    let key: u64 = read_key(&args);
    let mode = get_cipher_mode(args);
    let encrypted = my_des::encrypt(&input, key, mode);
    let succcess = write_output(args, &encrypted, false);
    return Ok(());
}

// Decrypt according to arguments.
fn decrypt(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    // TODO: actual error handling...
    let input = read_input(args, false);
    let key: u64 = read_key(&args);
    let mode = get_cipher_mode(args);
    let encrypted = my_des::decrypt(&input, key, mode);
    let success = write_output(args, &encrypted, true);
    return Ok(());
}

fn main() -> Result<(), Box<dyn Error>> {
    let modes = ["ECB", "CBC"];

    let matches = App::new("my_des")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(SubCommand::with_name("encrypt"))
        .subcommand(SubCommand::with_name("decrypt"))
        .arg(Arg::with_name("mode")
             .short("m").long("mode")
             .required(true)
             .takes_value(true)
             .possible_values(&modes)
             .help("ECB or CBC"))
        .arg(Arg::with_name("in")
             .short("i").long("in")
             .required(true)
             .takes_value(true)
             .help("Input file"))
        .arg(Arg::with_name("out")
             .short("o").long("out")
             .required(true)
             .takes_value(true)
             .help("Output file"))
        .arg(Arg::with_name("key")
             .short("k").long("key")
             .required(true)
             .takes_value(true)
             .help("Key file"))
        .get_matches();

    let result = match matches.subcommand() {
        ("encrypt", Some(_)) => encrypt(&matches),
        ("decrypt", Some(_)) => decrypt(&matches),
        _ => panic!("Action should be encrypt or decrypt!"),
    };

    return result;
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
