use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

fn main() -> io::Result<()> {
    // Paths for the source files and their corresponding output files
    let chimera_source = Path::new("../target/i686-unknown-linux-musl/release/chimera");
    let chimera_out = Path::new("./bin/chimera.zlib");

    // Ensure the source files exist
    if !chimera_source.exists() {
        panic!("Chimera source file does not exist: {:?}", chimera_source);
    }

    // Create the output directory if it doesn't exist
    fs::create_dir_all("./bin")?;

    // Compress chimera
    compress_file(&chimera_source, &chimera_out)?;

    Ok(())
}

fn compress_file(source_path: &Path, out_path: &Path) -> io::Result<()> {
    // Read the file's contents
    let file_contents = fs::read(source_path)?;

    // Compress the data using zlib (flate2)
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&file_contents)?;
    let compressed_data = encoder.finish()?;

    // Write the compressed data to the specified output file
    let mut out_file = File::create(out_path)?;
    out_file.write_all(&compressed_data)?;

    Ok(())
}
