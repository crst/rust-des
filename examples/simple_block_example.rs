extern crate my_des;


fn main() {
    let sample_inp: u64 = 0x0123456789ABCDEF;
    let sample_key: u64 = 0x133457799BBCDFF1;

    let expected_encrypted_value: u64 = 0x85E813540F0AB405;

    let keys: [u64; 16] = my_des::generate_round_keys(sample_key);
    let enc: u64 = my_des::encrypt_block(sample_inp, keys);
    let dec: u64 = my_des::decrypt_block(enc, keys);
    println!("ENC({}, {}) should be: {}", sample_inp, sample_key, expected_encrypted_value);
    println!("Actually encrypted value: {}", enc);
    println!("DEC({}, {}) is: {}", enc, sample_key, dec);
}
