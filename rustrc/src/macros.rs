use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitStr};
use reqwest::blocking::get;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;
use std::fs::File;
use std::path::Path;


macro_rules! cmd {
    ($cmd:expr $(,$arg:expr)*) => {
        {
            let mut cmd = $crate::client::Command::new($cmd);
            $(
                cmd = cmd.arg($arg);
            )*

            cmd
        }
    };
}

#[proc_macro]
pub fn download_and_embed(input: TokenStream) -> TokenStream {
    // Parse the input URL
    let url = parse_macro_input!(input as LitStr).value();

    // Generate a unique file name based on the URL
    let file_name = format!("{}.gz", md5::compute(&url).to_string());
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join(&file_name);

    // Download and compress the file
    let response = get(&url).expect("Failed to download file");
    let content = response.bytes().expect("Failed to read response body");

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&content).expect("Failed to compress data");
    let compressed_data = encoder.finish().expect("Failed to finish compression");

    // Write the compressed data to a file in the build output directory
    let mut file = File::create(&dest_path).expect("Failed to create file");
    file.write_all(&compressed_data).expect("Failed to write data");

    // Generate the output TokenStream using include_bytes!
    let output = quote! {
        include_bytes!(concat!(env!("OUT_DIR"), "/", #file_name))
    };

    output.into()
}
