mod data;


fn permute(block: u64, block_size: u8, permutation: &[u8]) -> u64 {
    // Permutation of the input block. Since this implementation is
    // somewhat generic, `block` may actually be less than 64
    // bits. Therefore we need to additionally specify the true block
    // size as a parameter.
    let mut result: u64 = 0;

    for &pos in permutation.iter() {
        result <<= 1;
        let p: u8 = block_size - pos;
        result |= (block & (1 << p)) >> p;
    }

    return result;
}

/// Generate all 16 round keys from the original key.
pub fn generate_round_keys(key: u64) -> [u64; 16] {
    let mut keys: [u64; 16] = [0; 16];

    // We do not split the key, but keep both C and D as one u64.
    let mut cd: u64 = permute(key, 64, &data::PC1);

    // Mask to get the two leftmost bits which will be shifted around.
    let data_mask = (1 << 55) | (1 << 27);
    // Mask to reset bits which should be zero after regular shifting.
    let zero_mask = (0xFF << 56) | (1 << 28);

    for (i, &num_shifts) in data::LSHIFTS.iter().enumerate() {
        // Just run multiple shifts as a sequence of single shifts.
        for _ in 0..num_shifts {
            let data: u64 = (cd & data_mask) >> 27;
            cd = (cd << 1) & !zero_mask | data;
        }
        keys[i] = permute(cd, 56, &data::PC2);
    }

    return keys;
}

fn f(block: u64, key: u64) -> u64 {
    let mut result: u64 = 0;
    // Compute the input value for the S-Boxes.
    let tmp: u64 = permute(block, 32, &data::E) ^ key;

    // Apply the S-Boxes via the direct lookup table.
    let mask: u64 = 0b111111;
    for (i, sbox) in data::BOXES.iter().enumerate() {
        let val: u64 = (tmp & (mask << (42 - (i*6)))) >> (42 - (i*6));
        result = (result << 4) | sbox[data::BOX_LOOKUP[val as usize]] as u64;
    }

    // Return permutation of the output from the S-Boxes.
    return permute(result, 32, &data::P);
}

fn run_network(block: u64, keys: [u64; 16]) -> u64 {
    // Start with the initial permutation.
    let lr: u64 = permute(block, 64, &data::IP);

    // Split block into L and R.
    let mut l: u64 = (lr & 0xFF_FF_FF_FF_00_00_00_00) >> 32;
    let mut r: u64 = lr & 0x00_00_00_00_FF_FF_FF_FF;

    // Run all 16 rounds of the Feistel network.
    for &key in keys.iter() {
        let tmp: u64 = l;
        l = r;
        r = tmp ^ f(r, key);
    }

    // Switch L and R.
    let switched: u64 = (r << 32) | l;

    // Last step is running the inverse initial permutation.
    return permute(switched, 64, &data::IIP);
}

pub fn encrypt_block(block: u64, keys: [u64; 16]) -> u64 {
    // Encryption is simply running the network.
    return run_network(block, keys);
}

pub fn decrypt_block(block: u64, keys: [u64; 16]) -> u64 {
    // Decryption is running the network with reversed keys.
    let mut rks: [u64; 16] = [0; 16];
    for (i, &key) in keys.iter().rev().enumerate() {
        rks[i] = key;
    }
    return run_network(block, rks);
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::prelude::*;

    // Test invariants with random data.

    #[test]
    fn inv_permutation() {
        // Running a permutation with IP followed by an permutation
        // with IIP should not change the value. Test this for 1000
        // random blocks.
        for _ in 0..1000 {
            let mut rng = rand::thread_rng();
            let block: u64 = rng.gen_range(0, 2^64);
            assert_eq!(block, permute(permute(block, 64, &data::IP), 64, &data::IIP),
                       "Failed for input: {}", block);
        }
    }

    #[test]
    fn inv_encrypt_decrypt() {
        // Encryption followed by decryption should return the
        // unchanged input value. Test this for 1000 random blocks.
        for _ in 0..1000 {
            let mut rng = rand::thread_rng();
            let sample_inp: u64 = rng.gen_range(0, 2^64);
            let sample_key: u64 = rng.gen_range(0, 2^64);

            let keys = generate_round_keys(sample_key);
            assert_eq!(sample_inp, decrypt_block(encrypt_block(sample_inp, keys), keys),
                       "Failed for input: {}", sample_inp);
        }
    }

    // ------------------------------------------------------------------------

    // All following "dev" tests are based on examples from:
    // http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

    #[test]
    fn dev_key_generation() {
        let key: u64 = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001;

        let keys: [u64; 16] = generate_round_keys(key);

        let expected_output: [u64; 16] = [
            0b000110_110000_001011_101111_111111_000111_000001_110010,
            0b011110_011010_111011_011001_110110_111100_100111_100101,
            0b010101_011111_110010_001010_010000_101100_111110_011001,
            0b011100_101010_110111_010110_110110_110011_010100_011101,
            0b011111_001110_110000_000111_111010_110101_001110_101000,
            0b011000_111010_010100_111110_010100_000111_101100_101111,
            0b111011_001000_010010_110111_111101_100001_100010_111100,
            0b111101_111000_101000_111010_110000_010011_101111_111011,
            0b111000_001101_101111_101011_111011_011110_011110_000001,
            0b101100_011111_001101_000111_101110_100100_011001_001111,
            0b001000_010101_111111_010011_110111_101101_001110_000110,
            0b011101_010111_000111_110101_100101_000110_011111_101001,
            0b100101_111100_010111_010001_111110_101011_101001_000001,
            0b010111_110100_001110_110111_111100_101110_011100_111010,
            0b101111_111001_000110_001101_001111_010011_111100_001010,
            0b110010_110011_110110_001011_000011_100001_011111_110101
        ];

        assert_eq!(keys, expected_output);
    }

    #[test]
    fn dev_ip_permutation() {
        let input: u64 = 0b0000_0001_0010_0011_0100_0101_0110_0111_1000_1001_1010_1011_1100_1101_1110_1111;
        let expected_output: u64 = 0b1100_1100_0000_0000_1100_1100_1111_1111_1111_0000_1010_1010_1111_0000_1010_1010;

        assert_eq!(expected_output, permute(input, 64, &data::IP));
    }

    #[test]
    fn dev_f() {
        let r: u64 = 0b1111_0000_1010_1010_1111_0000_1010_1010;
        let k: u64 = 0b000110_110000_001011_101111_111111_000111_000001_110010;

        let expected_output: u64 = 0b0010_0011_0100_1010_1010_1001_1011_1011;

        assert_eq!(f(r, k), expected_output);
    }

    #[test]
    fn dev_encrypt_block() {
        let sample_inp: u64 = 0x0123456789ABCDEF;
        let sample_key: u64 = 0x133457799BBCDFF1;

        let keys: [u64; 16] = generate_round_keys(sample_key);

        let expected_output: u64 = 0x85E813540F0AB405;

        assert_eq!(encrypt_block(sample_inp, keys), expected_output);
    }

    // ------------------------------------------------------------------------

    #[test]
    fn impl_recurrence_relation() {
        // Test from https://people.csail.mit.edu/rivest/pubs/Riv85.txt
        let mut input: u64 = 0x94_74_B8_E8_C7_3B_CA_7D;

        let expected_output: [u64; 16] = [
            0x8D_A7_44_E0_C9_4E_5E_17,
            0x0C_DB_25_E3_BA_3C_6D_79,
            0x47_84_C4_BA_50_06_08_1F,
            0x1C_F1_FC_12_6F_2E_F8_42,
            0xE4_BE_25_00_42_09_8D_13,
            0x7B_FC_5D_C6_AD_B5_79_7C,
            0x1A_B3_B4_D8_20_82_FB_28,
            0xC1_57_6A_14_DE_70_70_97,
            0x73_9B_68_CD_2E_26_78_2A,
            0x2A_59_F0_C4_64_50_6E_DB,
            0xA5_C3_9D_42_51_F0_A8_1E,
            0x72_39_AC_9A_61_07_DD_B1,
            0x07_0C_AC_85_90_24_12_33,
            0x78_F8_7B_6E_3D_FE_CF_61,
            0x95_EC_25_78_C2_C4_33_F0,
            0x1B_1A_2D_DB_4C_64_24_38
        ];


        for i in 0..16 {
            let keys: [u64; 16] = generate_round_keys(input);
            if i % 2 == 0 {
                input = encrypt_block(input, keys);
            } else {
                input = decrypt_block(input, keys);
            }
            assert_eq!(input, expected_output[i], "X({}) has unexpected value!", i);
        }
    }
}
