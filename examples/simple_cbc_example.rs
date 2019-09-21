use my_des;


fn main() {
    let sample_inp: Vec<u64> = vec![
        0x0123456789ABCDEF,
        0x0123456789ABCDEF,
        0x0123456789ABCDEF
    ];
    let sample_key: u64 = 0x85E813540F0AB405;
    println!("Sample input: {:?}", sample_inp);

    let ciphertext = my_des::encrypt(&sample_inp, sample_key, Box::new(my_des::CBC));
    println!("ECB cipher: {:?}", ciphertext);

    let plaintext = my_des::decrypt(&ciphertext, sample_key, Box::new(my_des::CBC));
    println!("Plaintext: {:?}", plaintext);
}
