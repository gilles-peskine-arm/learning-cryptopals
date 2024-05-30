use std::io::Write;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::cipher::generic_array::GenericArray;

const BLOCK_SIZE: usize = 16;

fn cbc_decrypt(key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE], data: &mut Vec<u8>) {
    let dec = aes::Aes128Dec::new(&GenericArray::from(key));
    let mut prev = iv;
    for block in data.chunks_mut(BLOCK_SIZE) {
        let cur: [u8; BLOCK_SIZE] = block.try_into().expect("eek");
        let mut array = GenericArray::from(cur);
        dec.decrypt_block(&mut array);
        for i in 0..BLOCK_SIZE {
            block[i] = array[i] ^ prev[i];
        }
        prev = cur;
    }
}

fn main() -> std::io::Result<()> {
    let base64 = {
        let mut spec = data_encoding::BASE64.specification();
        spec.ignore.push_str("\t\n\r ");
        spec.encoding().unwrap()
    };

    let input_base64 = std::fs::read_to_string("10.txt")?;
    let data: Vec<u8> = base64.decode(input_base64.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput,
                                         "invalid base64"))?;

    let key: [u8; BLOCK_SIZE] = *b"YELLOW SUBMARINE";
    let iv: [u8; BLOCK_SIZE] = data[0..BLOCK_SIZE].try_into().expect("eek");
    let mut content = data[BLOCK_SIZE..].to_vec();
    cbc_decrypt(key, iv, &mut content);

    std::io::stdout().write_all(content.as_slice())?;
    Ok(())
}
