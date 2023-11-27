pub enum AesMode {
    AES128 = 0,
    AES192 = 1,
    AES256 = 2,
}

const RIJNDAEL_AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

const INVERSE_RIJNDAEL_AES_SBOX: [u8; 256] = [ 
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

const NK: [usize; 3] = [4, 6, 8];
const NR: [usize; 3] = [10, 12, 14];

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    let mut result = [0; 4];
    for i in 0..4 {
        result[i] = RIJNDAEL_AES_SBOX[word[i] as usize];
    }
    result
}

fn xor_words(word_1: [u8; 4], word_2: [u8; 4]) -> [u8; 4] {
    let mut result = [0; 4];
    for i in 0..4 {
        result[i] = word_1[i] ^ word_2[i];
    }
    result
}

fn rot_word(word: [u8; 4]) -> [u8; 4] {
    let mut result = [0; 4];
    for i in 0..4 {
        result[i] = word[(i + 1) % 4];
    }
    result
}

fn g_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    let mut high_bit;
    for _ in 0..8 {
        if (b & 1) != 0 {
            p ^= a;
        }
        high_bit = (a & 0x80) == 0x80;
        a <<= 1;
        if high_bit {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn key_expansion(key: &[u8], mode: &usize) -> Vec<[u8; 4]> {
    let mut expanded_key = vec![[0; 4]; (NR[*mode] + 1) * 4];
    let mut index = 0;

    let (mut byte_one, mut byte_two, mut byte_three, mut byte_four) = (0, 1, 2, 3);
    while index != NK[*mode] {
        expanded_key[index] = [key[byte_one], key[byte_two], key[byte_three], key[byte_four]];
        byte_one += 4; 
        byte_two += 4;
        byte_three += 4;
        byte_four += 4;
        index += 1;
    }
    let mut word;
    let mut r_index = 0;

    while index != (NR[*mode] + 1) * 4 {
        word = expanded_key[index - 1];
        if index % NK[*mode] == 0 {
            let mut temp = sub_word(rot_word(word));
            temp[0] ^= RCON[r_index];
            word = temp;
            r_index += 1;
        } else if NK[*mode] == 8 && index % 4 == 0 {
            word = sub_word(word);
        }
        expanded_key[index] = xor_words(expanded_key[index - NK[*mode]], word);
        index += 1;
    }
    expanded_key
}

fn pad(text: &[u8]) -> Vec<u8> {
    let mut result = vec![0; text.len()];
    let mut pad_size = 16 - (text.len() % 16);
    if pad_size == 0 {
        pad_size = 16;
    }
    result[..text.len()].copy_from_slice(text);
    for _ in 0..pad_size {
        result.push(pad_size as u8);
    }
    result
}

fn sub_bytes(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in 0..state.len() {
        for j in 0..state[i].len() {
            state[i][j] = RIJNDAEL_AES_SBOX[state[i][j] as usize];
        }
    }
    state
}

fn shift_rows(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    (state[1][0], state[1][1], state[1][2], state[1][3]) = (state[1][1], state[1][2], state[1][3], state[1][0]);
    (state[2][0], state[2][1], state[2][2], state[2][3]) = (state[2][2], state[2][3], state[2][0], state[2][1]);
    (state[3][0], state[3][1], state[3][2], state[3][3]) = (state[3][3], state[3][0], state[3][1], state[3][2]);
    state
}

fn mix_columns(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in 0..4 {
        let mut temp = [0; 4];
        for j in 0..4 {
            temp[j] = state[j][i];
        }
        state[0][i]= g_mul(temp[0], 2) ^ g_mul(temp[3], 1) ^ g_mul(temp[2], 1) ^ g_mul(temp[1], 3);
        state[1][i]= g_mul(temp[1], 2) ^ g_mul(temp[0], 1) ^ g_mul(temp[3], 1) ^ g_mul(temp[2], 3);
        state[2][i]= g_mul(temp[2], 2) ^ g_mul(temp[1], 1) ^ g_mul(temp[0], 1) ^ g_mul(temp[3], 3);
        state[3][i]= g_mul(temp[3], 2) ^ g_mul(temp[2], 1) ^ g_mul(temp[1], 1) ^ g_mul(temp[0], 3);
    }
    state
}

fn add_round_key(mut state: [[u8; 4]; 4], key: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] ^= key[j][i];
        }
    }
    state
}

fn inv_sub_bytes(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in 0..state.len() {
        for j in 0..state[i].len() {
            state[i][j] = INVERSE_RIJNDAEL_AES_SBOX[state[i][j] as usize];
        }
    }
    state
}

fn inv_shift_rows(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    (state[1][0], state[1][1], state[1][2], state[1][3]) = (state[1][3], state[1][0], state[1][1], state[1][2]);
    (state[2][0], state[2][1], state[2][2], state[2][3]) = (state[2][2], state[2][3], state[2][0], state[2][1]);
    (state[3][0], state[3][1], state[3][2], state[3][3]) = (state[3][1], state[3][2], state[3][3], state[3][0]);
    state
}

fn inv_mix_columns(mut state: [[u8; 4]; 4]) -> [[u8; 4]; 4] {
    for i in 0..4 {
        let mut temp = [0; 4];
        for j in 0..4 {
            temp[j] = state[j][i];
        }
        state[0][i]= g_mul(temp[0], 14) ^ g_mul(temp[3], 9) ^ g_mul(temp[2], 13) ^ g_mul(temp[1], 11);
        state[1][i]= g_mul(temp[1], 14) ^ g_mul(temp[0], 9) ^ g_mul(temp[3], 13) ^ g_mul(temp[2], 11);
        state[2][i]= g_mul(temp[2], 14) ^ g_mul(temp[1], 9) ^ g_mul(temp[0], 13) ^ g_mul(temp[3], 11);
        state[3][i]= g_mul(temp[3], 14) ^ g_mul(temp[2], 9) ^ g_mul(temp[1], 13) ^ g_mul(temp[0], 11);
    }
    state
}

pub fn encrypt(text: &[u8], key: &[u8], mode: AesMode) -> Result<Vec<u8>, String> {
    let input_bytes = pad(text);

    let mode_index = mode as usize;
    let key_schedule = key_expansion(key, &mode_index);

    let mut result = vec![0; input_bytes.len()];
    let mut start_index = 0;
    for block in input_bytes.chunks(16) {
        let temp = encrypt_block(block.try_into().unwrap(), &key_schedule, &mode_index);
        let end_index = start_index + temp.len();
        result[start_index..end_index].copy_from_slice(&temp[..]);
        start_index += temp.len();
    }
    Ok(result)
}

fn encrypt_block(block: [u8; 16], key_schedule: &[[u8; 4]], mode: &usize) -> [u8; 16] {
    let mut result = [0; 16];
    let mut state = [[0; 4]; 4];

    for i in 0..16 {
        state[i % 4][i / 4] = block[i];
    }
    state = add_round_key(state, key_schedule[0..4].to_vec().try_into().unwrap());

    for i in 1..NR[*mode] {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_round_key(state, key_schedule[i * 4..(i+1)*4].to_vec().try_into().unwrap());
    }
    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(state, key_schedule[4 * NR[*mode]..4 * NR[*mode] + 4].to_vec().try_into().unwrap());

    for i in 0..4 {
        for j in 0..4 {
            result[4 * j + i] = state[i][j];
        }
    }
    result
}

pub fn dencrypt(text: &[u8], key: &[u8], mode: AesMode) -> Result<String, String> {
    let mode_index = mode as usize;
    let key_schedule = key_expansion(key, &mode_index);
    let mut result = vec![0; text.len()];
    let mut start_index = 0;
    for block in text.chunks(16) {
        let temp = dencrypt_block(block.try_into().unwrap(), &key_schedule, &mode_index);
        let end_index = start_index + temp.len();
        result[start_index..end_index].copy_from_slice(&temp[..]);
        start_index += temp.len();
    }
    let text_size = *result.last().unwrap() as usize;
    Ok(String::from_utf8(result[..result.len() - text_size].to_vec()).unwrap())
}

fn dencrypt_block(block: [u8; 16], key_schedule: &[[u8; 4]], mode: &usize) -> [u8; 16] {
    let mut result = [0; 16];
    let mut state = [[0; 4]; 4];
    
    for i in 0..16 {
        state[i % 4][i / 4] = block[i];
    }
    state = add_round_key(state, key_schedule[4 * NR[*mode]..4 * NR[*mode] + 4].to_vec().try_into().unwrap());
    state = inv_shift_rows(state);
    state = inv_sub_bytes(state);

    for i in (1..NR[*mode]).rev() {
        state = add_round_key(state, key_schedule[i * 4..(i+1)*4].to_vec().try_into().unwrap());
        state = inv_mix_columns(state);
        state = inv_shift_rows(state);
        state = inv_sub_bytes(state);
    }
    state = add_round_key(state, key_schedule[0..4].to_vec().try_into().unwrap());

    for i in 0..4 {
        for j in 0..4 {
            result[4 * j + i] = state[i][j];
        }
    }
    result
}