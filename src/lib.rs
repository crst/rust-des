extern crate rand;

pub mod des;
use rand::prelude::*;


pub struct ECB;
impl ECB {
    pub fn new() -> ECB { ECB }
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
    fn encrypt(&mut self, plaintext: &Vec<u64>, key: u64) -> Vec<u64>;
    fn decrypt(&mut self, ciphertext: &Vec<u64>, key: u64) -> Vec<u64>;
}

pub fn encrypt(plaintext: &Vec<u64>, key: u64, mode: &mut Box<dyn Cipher>) -> Vec<u64> {
    return mode.encrypt(plaintext, key);
}

pub fn decrypt(ciphertext: &Vec<u64>, key: u64, mode: &mut Box<dyn Cipher>) -> Vec<u64> {
    return mode.decrypt(ciphertext, key);
}

impl Cipher for ECB {
    fn encrypt(&mut self, plaintext: &Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::new();
        let keys = des::generate_round_keys(key);
        for &block in plaintext.iter() {
            result.push(des::encrypt_block(block, keys));
        }
        return result;
    }

    fn decrypt(&mut self, ciphertext: &Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::new();
        let keys = des::generate_round_keys(key);
        for &block in ciphertext.iter() {
            result.push(des::decrypt_block(block, keys));
        }
        return result;
    }
}

impl Cipher for CBC {
    fn encrypt(&mut self, plaintext: &Vec<u64>, key: u64) -> Vec<u64> {
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

    fn decrypt(&mut self, ciphertext: &Vec<u64>, key: u64) -> Vec<u64> {
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
            let ciphertext = encrypt(&plaintext, key, &mut mode);

            let mut mode: Box<dyn Cipher> = Box::new(ECB::new());
            let decrypted = decrypt(&ciphertext, key, &mut mode);

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
            let ciphertext = encrypt(&plaintext, key, &mut mode);

            let mut mode: Box<dyn Cipher> = Box::new(CBC::new());
            let decrypted = decrypt(&ciphertext, key, &mut mode);

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
            let ecb_ciphertext = encrypt(&plaintext, key, &mut ecb_mode);
            let cbc_ciphertext = encrypt(&plaintext, key, &mut cbc_mode);

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
            let cbc_ciphertext = encrypt(&plaintext, key, &mut cbc_mode);
            let wrong_plaintext = decrypt(&cbc_ciphertext, key, &mut ecb_mode);

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
            let ecb_ciphertext = encrypt(&plaintext, key, &mut ecb_mode);
            let wrong_plaintext = decrypt(&ecb_ciphertext, key, &mut cbc_mode);

            assert_ne!(plaintext, wrong_plaintext);
        }
    }

}
