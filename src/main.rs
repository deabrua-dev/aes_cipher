mod rijndael_aes;

use rijndael_aes::*;

fn main() {
    let text = b"Hello world!!!! My name is Stew.";
    let key = b"Hello world!!!!!Hello world!!!!!";
    println!("24 43 177 73 56 221 56 197 41 93 22 119 154 201 203 34");
    // println!("7 199 31 226 85 27 164 216 210 149 112 91 40 47 215 87");
    let encrypted = encrypt(&text.clone(), key, AesMode::AES256).unwrap();
    println!("{}", encrypted.len());
    let arr: [u8; 32] = encrypted.try_into().unwrap();
    for i in arr {
        print!("{:0>2x} ", i);
    }
    println!();
    println!("{}", dencrypt(&arr, key, AesMode::AES256).unwrap());
}
