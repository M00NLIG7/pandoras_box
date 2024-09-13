use flate2::write::GzEncoder;
use flate2::Compression;
use proc_macro::TokenStream;
use quote::quote;
use reqwest::blocking::get;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use syn::{parse_macro_input, LitStr};

#[proc_macro]
pub fn download_and_embed(input: TokenStream) -> TokenStream {
    // Parse the input URL
    let url = parse_macro_input!(input as LitStr).value();

    // Generate a unique file name based on the URL
    let digest = md5::compute(&url);
    let file_name = format!("{:x}.gz", digest);

    // Determine the output directory
    let out_dir = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir());
    let dest_path = out_dir.join(&file_name);

    // Only perform the download and compression when not in Rust Analyzer
    #[cfg(not(proc_macro_def_site))]
    {
        // Download and compress the file
        let response = get(&url).expect("Failed to download file");
        let content = response.bytes().expect("Failed to read response body");

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&content)
            .expect("Failed to compress data");
        let compressed_data = encoder.finish().expect("Failed to finish compression");

        // Write the compressed data to a file in the selected directory
        let mut file = File::create(&dest_path).expect("Failed to create file");
        file.write_all(&compressed_data)
            .expect("Failed to write data");
    }

    // Generate the output TokenStream using include_bytes!
    let dest_path_str = dest_path
        .to_str()
        .expect("Failed to convert path to string");
    let output = quote! {
        include_bytes!(#dest_path_str)
    };

    output.into()
}

