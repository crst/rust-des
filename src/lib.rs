extern crate rand;

pub mod des;
use rand::prelude::*;


pub struct ECB;
pub struct CBC;

pub trait Cipher {
    fn encrypt(&self, plaintext: &Vec<u64>, key: u64) -> Vec<u64>;
    fn decrypt(&self, ciphertext: &Vec<u64>, key: u64) -> Vec<u64>;
}

pub fn encrypt(plaintext: &Vec<u64>, key: u64, mode: Box<dyn Cipher>) -> Vec<u64> {
    return mode.encrypt(plaintext, key);
}

pub fn decrypt(ciphertext: &Vec<u64>, key: u64, mode: Box<dyn Cipher>) -> Vec<u64> {
    return mode.decrypt(ciphertext, key);
}

impl Cipher for ECB {
    fn encrypt(&self, plaintext: &Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::new();
        let keys = des::generate_round_keys(key);
        for &block in plaintext.iter() {
            result.push(des::encrypt_block(block, keys));
        }
        return result;
    }

    fn decrypt(&self, ciphertext: &Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::new();
        let keys = des::generate_round_keys(key);
        for &block in ciphertext.iter() {
            result.push(des::decrypt_block(block, keys));
        }
        return result;
    }
}

impl Cipher for CBC {
    fn encrypt(&self, plaintext: &Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::with_capacity(plaintext.len() + 1);
        let keys = des::generate_round_keys(key);

        let mut initialization_vector: u64 = 0;
        while initialization_vector == 0 {
            // Avoid an empty initialization_vector.
            initialization_vector = random_u64();
        }

        let random_block = random_u64();
        let mut b: u64 = des::encrypt_block(initialization_vector ^ random_block, keys);
        result.push(b);
        for &block in plaintext.iter() {
            b = des::encrypt_block(b ^ block, keys);
            result.push(b);
        }

        return result;
    }

    fn decrypt(&self, ciphertext: &Vec<u64>, key: u64) -> Vec<u64> {
        let mut result: Vec<u64> = Vec::with_capacity(ciphertext.len() - 1);
        let keys = des::generate_round_keys(key);

        let mut initialization_vector: u64 = ciphertext[0];
        for &block in ciphertext.iter().skip(1) {
            result.push(initialization_vector ^ des::decrypt_block(block, keys));
            initialization_vector = block;
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

            let ciphertext = encrypt(&plaintext, key, Box::new(ECB));
            let decrypted = decrypt(&ciphertext, key, Box::new(ECB));

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

            let ciphertext = encrypt(&plaintext, key, Box::new(CBC));
            let decrypted = decrypt(&ciphertext, key, Box::new(CBC));

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

            let ecb_ciphertext = encrypt(&plaintext, key, Box::new(ECB));
            let cbc_ciphertext = encrypt(&plaintext, key, Box::new(CBC));

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

            let cbc_ciphertext = encrypt(&plaintext, key, Box::new(CBC));
            let wrong_plaintext = decrypt(&cbc_ciphertext, key, Box::new(ECB));

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

            let ecb_ciphertext = encrypt(&plaintext, key, Box::new(ECB));
            let wrong_plaintext = decrypt(&ecb_ciphertext, key, Box::new(CBC));

            assert_ne!(plaintext, wrong_plaintext);
        }
    }

}
