extern crate rand;
extern crate num_cpus;

pub mod des;

use rand::prelude::*;
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::thread;


// To process each chunk in parallel, we store parts together with the
// position within the chunk.
#[derive(Debug)]
struct ChunkPart {
    position: usize,
    data: Vec<u64>,
}

pub struct ECB;
impl ECB {
    pub fn new() -> ECB { ECB }

    // Parallel encrypt or decrypt.
    pub fn process(&self, f: &'static (dyn Fn(u64, [u64; 16]) -> u64 + Sync), input: Vec<u64>, key: u64) -> Vec<u64> {
        let keys = des::generate_round_keys(key);
        let mut result: Vec<u64> = vec![0u64; input.len()];

        // Use all available CPU's.
        let num_threads: usize = num_cpus::get();
        let part_size: usize = input.len() / num_threads;

        // We'll read the input from read-only shared memory, but then
        // collect the results via messages.
        let input_ref = Arc::new(RwLock::new(input));
        let (sender, receiver) = mpsc::channel();
        let mut handles = vec![];

        // Each thread processes only one part of the input, and sends
        // the result to a channel from where we'll create the actual
        // result later.
        for t in 0..num_threads {
            let local_sender = mpsc::Sender::clone(&sender);
            let local_input_ref = Arc::clone(&input_ref);
            let handle = thread::spawn(move || {
                let local_data = local_input_ref.read().unwrap();
                let idx = t * part_size;
                let local_chunk_part = match t < num_threads - 1 {
                    true => &local_data[idx..idx+part_size],
                    false => &local_data[idx..],
                };

                let mut local_result: Vec<u64> = Vec::new();
                for &block in local_chunk_part.iter() {
                    local_result.push(f(block, keys));
                }

                local_sender.send(ChunkPart {
                    position: t,
                    data: local_result,
                }).unwrap();
            });
            handles.push(handle);
        }
        // We need to drop the original sender, so it doesn't block.
        drop(sender);

        // Collect one message from each thread and build the result
        // from the different parts.
        for msg in receiver {
            for (i, &d) in msg.data.iter().enumerate() {
                result[msg.position * part_size + i] = d;
            }
        }

        // Make sure we wait for each thread.
        for handle in handles {
            handle.join().unwrap();
        }

        return result;
    }
}

pub struct CBC {
    is_active: bool,
    prev_block: u64,
}
impl CBC {
    pub fn new() -> CBC {
        let mut prev_block: u64 = 0;
        while prev_block == 0 {
            // Avoid an empty initialization_vector.
            prev_block = random_u64();
        }
        CBC {
            is_active: false,
            prev_block: prev_block,
        }
    }
}

pub trait Cipher {
    fn encrypt(&mut self, plaintext: Vec<u64>, key: u64) -> Vec<u64>;
    fn decrypt(&mut self, ciphertext: Vec<u64>, key: u64) -> Vec<u64>;
}

pub fn encrypt(plaintext: Vec<u64>, key: u64, mode: &mut Box<dyn Cipher>) -> Vec<u64> {
    return mode.encrypt(plaintext, key);
}

pub fn decrypt(ciphertext: Vec<u64>, key: u64, mode: &mut Box<dyn Cipher>) -> Vec<u64> {
    return mode.decrypt(ciphertext, key);
}

impl Cipher for ECB {
    fn encrypt(&mut self, plaintext: Vec<u64>, key: u64) -> Vec<u64> {
        return self.process(&des::encrypt_block, plaintext, key);
    }

    fn decrypt(&mut self, ciphertext: Vec<u64>, key: u64) -> Vec<u64> {
        return self.process(&des::decrypt_block, ciphertext, key);
    }
}

impl Cipher for CBC {
    fn encrypt(&mut self, plaintext: Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::with_capacity(plaintext.len() + 1);
        let keys = des::generate_round_keys(key);

        if !self.is_active {
            // Add a random block at the beginning, so that we do not need
            // to share the initialization vector.
            let random_block = random_u64();
            self.prev_block = des::encrypt_block(self.prev_block ^ random_block, keys);
            result.push(self.prev_block);
            self.is_active = true;
        }

        // Encrypt actual data blocks.
        for &block in plaintext.iter() {
            self.prev_block = des::encrypt_block(self.prev_block ^ block, keys);
            result.push(self.prev_block);
        }

        return result;
    }

    fn decrypt(&mut self, ciphertext: Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::with_capacity(ciphertext.len() - 1);
        let keys = des::generate_round_keys(key);

        let mut skip_blocks = 0;
        if !self.is_active {
            self.prev_block = ciphertext[0];
            self.is_active = true;
            skip_blocks = 1;
        }
        for &block in ciphertext.iter().skip(skip_blocks) {
            result.push(self.prev_block ^ des::decrypt_block(block, keys));
            self.prev_block = block;
        }

        return result;
    }
}


pub fn random_u64() -> u64 {
    let mut result: u64 = 0;
    let mut buffer: [u8; 8] = [0; 8];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut buffer);
    for &buf in buffer.iter() {
        result <<= 8;
        result |= buf as u64;
    }
    return result;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_encrypt_decrypt_ecb() {
        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let num_bytes = rng.gen_range(0, 64);
            let mut plaintext: Vec<u64> = Vec::with_capacity(num_bytes);
            for _ in 0..num_bytes {
                plaintext.push(random_u64());
            }

            let key: u64 = random_u64();

            let mut mode: Box<dyn Cipher> = Box::new(ECB::new());
            let ciphertext = encrypt(plaintext.to_vec(), key, &mut mode);

            let mut mode: Box<dyn Cipher> = Box::new(ECB::new());
            let decrypted = decrypt(ciphertext.to_vec(), key, &mut mode);

            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn inv_encrypt_decrypt_cbc() {
        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let num_bytes = rng.gen_range(0, 64);
            let mut plaintext: Vec<u64> = Vec::with_capacity(num_bytes);
            for _ in 0..num_bytes {
                plaintext.push(random_u64());
            }

            let key: u64 = random_u64();

            let mut mode: Box<dyn Cipher> = Box::new(CBC::new());
            let ciphertext = encrypt(plaintext.to_vec(), key, &mut mode);

            let mut mode: Box<dyn Cipher> = Box::new(CBC::new());
            let decrypted = decrypt(ciphertext.to_vec(), key, &mut mode);

            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn ecb_does_not_equal_cbc() {
        // ECB and CBC ciphertexts for the same plaintext should
        // (basically) never be the same.
        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let num_bytes = rng.gen_range(2, 64);
            let mut plaintext: Vec<u64> = Vec::with_capacity(num_bytes);
            for _ in 0..num_bytes {
                plaintext.push(random_u64());
            }

            let key: u64 = random_u64();

            let mut ecb_mode: Box<dyn Cipher> = Box::new(ECB::new());
            let mut cbc_mode: Box<dyn Cipher> = Box::new(CBC::new());
            let ecb_ciphertext = encrypt(plaintext.to_vec(), key, &mut ecb_mode);
            let cbc_ciphertext = encrypt(plaintext.to_vec(), key, &mut cbc_mode);

            for i in 0..num_bytes {
                if i == 0 || cbc_ciphertext[i-1] != 0 {
                    assert_ne!(ecb_ciphertext[i], cbc_ciphertext[i]);

                    // Actually relevant comparison, since the CBC cipher
                    // added one random block at the beginning.
                    assert_ne!(ecb_ciphertext[i], cbc_ciphertext[i+1]);
                } else {
                    // If by chance the previously encrypted CBC block
                    // was 0, both ECB and CBC blocks should be the
                    // same in that case.
                    assert_eq!(ecb_ciphertext[i], cbc_ciphertext[i+1]);
                }
            };
        }
    }

    #[test]
    fn ecb_does_not_decrypt_cbc() {
        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let num_bytes = rng.gen_range(2, 64);
            let mut plaintext: Vec<u64> = Vec::with_capacity(num_bytes);
            for _ in 0..num_bytes {
                plaintext.push(random_u64());
            }

            let key: u64 = random_u64();

            let mut ecb_mode: Box<dyn Cipher> = Box::new(ECB::new());
            let mut cbc_mode: Box<dyn Cipher> = Box::new(CBC::new());
            let cbc_ciphertext = encrypt(plaintext.to_vec(), key, &mut cbc_mode);
            let wrong_plaintext = decrypt(cbc_ciphertext.to_vec(), key, &mut ecb_mode);

            assert_ne!(plaintext, wrong_plaintext);
        }
    }

    #[test]
    fn cbc_does_not_decrypt_ecb() {
        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            let num_bytes = rng.gen_range(2, 64);
            let mut plaintext: Vec<u64> = Vec::with_capacity(num_bytes);
            for _ in 0..num_bytes {
                plaintext.push(random_u64());
            }

            let key: u64 = random_u64();

            let mut ecb_mode: Box<dyn Cipher> = Box::new(ECB::new());
            let mut cbc_mode: Box<dyn Cipher> = Box::new(CBC::new());
            let ecb_ciphertext = encrypt(plaintext.to_vec(), key, &mut ecb_mode);
            let wrong_plaintext = decrypt(ecb_ciphertext.to_vec(), key, &mut cbc_mode);

            assert_ne!(plaintext, wrong_plaintext);
        }
    }

}
