use clap::Parser;

use std::fs::File;
use std::io::{prelude::*, SeekFrom};

use generic_array::{typenum::U16, GenericArray};

use digest::Digest;
use sha1::Sha1;
use sha2::Sha512;

use aes::{
    cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit},
    Aes256Dec,
};
use cbc::Decryptor as CBCDecryptor;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, help = "Allow file overwrite")]
    force: bool,
    #[arg(long, help = "Don't write file")]
    no_write: bool,
    #[arg(long, hide = true)]
    override_password: bool,
    file: std::path::PathBuf,
    #[arg(required_unless_present = "override_password")]
    password: Option<String>,
}

const IV_OFFSET: u64 = 0x43;
const DATA_OFFSET: u64 = 0xA3;
const CHUNK_SIZE: u64 = 0x8000;

fn hexstring(arr: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(arr.len() * 2);
    for c in arr {
        write!(&mut s, "{:02x}", c).unwrap();
    }
    s
}

fn main() {
    let args = Args::parse();
    if !args.file.is_file() {
        panic!("Path is not file")
    }

    let new_file_name = args.file.with_extension("");
    if !args.no_write & new_file_name.exists() & !args.force {
        panic!("Destination file already exists")
    }

    let mut enc_file = File::open(args.file).unwrap();

    let mut magic = [0u8; 7];
    enc_file.read_exact(&mut magic).unwrap();

    // check "EZC" magic
    if magic[..3] != [0x45, 0x5a, 0x43] {
        panic!("File is not EasyCrypt file")
    }

    if magic[3] != 2 {
        panic!("Unsupported EasyCrypt version (V{}.{})", magic[3], magic[4]);
    }

    println!("Decrypting Easycrypt V{}.{} file...", magic[3], magic[4]);

    enc_file.seek(SeekFrom::Start(IV_OFFSET)).unwrap();
    let mut iv = [0u8; 16];
    enc_file.read_exact(&mut iv).unwrap();

    let mut salt = [0u8; 16];
    enc_file.read_exact(&mut salt).unwrap();

    let mut hash = [0u8; 64];
    enc_file.read_exact(&mut hash).unwrap();

    if !args.override_password {
        let mut keyhasher = Sha512::new();
        keyhasher.update(args.password.unwrap());
        keyhasher.update(salt);
        let result = keyhasher.finalize();
        if GenericArray::from_slice(&hash) != &result {
            panic!("Password is incorrect")
        }
    }

    let key = GenericArray::from_slice(&hash[..32]);

    let checksum_offset = enc_file.seek(SeekFrom::End(-0x20)).unwrap();
    let mut src_checksum = [0u8; 32];
    enc_file.read_exact(&mut src_checksum).unwrap();
    let data_length = checksum_offset - DATA_OFFSET;

    let aes_cbc_dec = CBCDecryptor::<Aes256Dec>::new(key, &iv.into());
    let src_checksum = aes_cbc_dec
        .decrypt_padded_mut::<Pkcs7>(&mut src_checksum)
        .unwrap();
    println!("Source checksum: {}", hexstring(src_checksum));

    enc_file.seek(SeekFrom::Start(DATA_OFFSET)).unwrap();
    let mut aes_cbc_dec = CBCDecryptor::<Aes256Dec>::new(key, &iv.into());
    let mut processed_bytes = 0;
    let mut buf = [0u8; CHUNK_SIZE as usize];
    let mut dec_file = if args.no_write {
        None
    } else {
        Some(File::create(new_file_name).unwrap())
    };
    let mut filehasher = Sha1::new();

    for _ in 0..((data_length - 0x10) / CHUNK_SIZE) {
        enc_file.read_exact(&mut buf).unwrap();
        unsafe {
            aes_cbc_dec.decrypt_blocks_mut(std::mem::transmute::<
                _,
                &mut [GenericArray<u8, U16>; (CHUNK_SIZE / 0x10) as usize],
            >(&mut buf));
        }
        filehasher.update(buf);
        if let Some(ref mut f) = dec_file {
            f.write_all(&buf).unwrap();
        }
        processed_bytes += CHUNK_SIZE;
    }

    let _ = enc_file.read(&mut buf).unwrap();
    let unpadded = aes_cbc_dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf[0..(data_length - processed_bytes) as usize])
        .unwrap();
    filehasher.update(unpadded);
    if let Some(ref mut f) = dec_file {
        f.write_all(unpadded).unwrap();
    }

    let calc_checksum = filehasher.finalize();
    println!("Calculated checksum: {}", hexstring(&calc_checksum));
    if GenericArray::from_slice(src_checksum) != &calc_checksum {
        println!("Warning: checksum mismatch");
    }
}
