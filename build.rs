// Copyright The ocicrypt Authors.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Read, Write};
use ttrpc_codegen::Customize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = vec!["src/utils/proto/keyprovider.proto"];
    #[cfg(feature = "keywrap-keyprovider")]
    tonic_build::configure()
        .build_server(true)
        .out_dir("src/utils/grpc")
        .compile(&protos, &["src/utils"])?;

    ttrpc_codegen::Codegen::new()
        .out_dir("src/utils/ttrpc")
        .inputs(&protos)
        .include("src/utils")
        .rust_protobuf()
        .customize(Customize {
            async_all: true,
            ..Default::default()
        })
        .run()
        .expect("Gen code failed.");

    // To fix clippy warnings of code generated from ttrpc_codegen
    replace_text_in_file(
        "src/utils/ttrpc/keyprovider_ttrpc.rs",
        "client: client",
        "client",
    )
    .unwrap();
    replace_text_in_file(
        "src/utils/ttrpc/keyprovider_ttrpc.rs",
        "Arc<std::boxed::Box<dyn KeyProviderService + Send + Sync>>",
        "Arc<dyn KeyProviderService + Send + Sync>",
    )
    .unwrap();

    Ok(())
}

fn replace_text_in_file(file_name: &str, from: &str, to: &str) -> Result<(), std::io::Error> {
    let mut src = File::open(file_name)?;
    let mut contents = String::new();
    src.read_to_string(&mut contents).unwrap();
    drop(src);

    let new_contents = contents.replace(from, to);

    let mut dst = File::create(&file_name)?;
    dst.write_all(new_contents.as_bytes())?;

    Ok(())
}
