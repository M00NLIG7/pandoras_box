use base64::{engine::general_purpose::STANDARD, Engine};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

fn main() -> io::Result<()> {
    // Specify the path to the file you want to encode
    // let source_file = Path::new("../target/release/chimera");

    // // Ensure the source file exists
    // if !source_file.exists() {
    //     panic!("Source file does not exist: {:?}", source_file);
    // }

    // // Read the file's contents
    // let file_contents = fs::read(source_file)?;

    // // Encode the contents to Base64
    // let encoded = STANDARD.encode(&file_contents);

    // // Compress the Base64 encoded data using zlib (flate2)
    // let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    // encoder.write_all(encoded.as_bytes())?;
    // let compressed_data = encoder.finish()?;

    // // Define the output directory and create it if it doesn't exist
    // let out_dir = Path::new("./bin");
    // fs::create_dir_all(out_dir)?;

    // // Write the compressed data to a file in the ./bin directory
    // let out_path = out_dir.join("chimera64.zlib");
    // let mut out_file = File::create(&out_path)?;

    // // Write the compressed data
    // out_file.write_all(&compressed_data)?;

    Ok(())
}
