use std::env;
use std::fs::*;
use std::io::Read;
use std::process::exit;

use pe_parser::{export_functions, import_functions, is_pe};

const COMMANDS: [(&str, fn(&[u8]) -> i32); 3] = [
    ("is-pe", is_pe),
    ("import-functions", import_functions),
    ("export-functions", export_functions),
];

fn run(command: &str, data: &[u8]) -> i32 {
    match COMMANDS.iter().find(|(name, _)| *name == command) {
        Some(&(_, func)) => func(data),
        None => panic!("Cannot find a command {}!", command),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Expected 2 arguments, found: {}", args.len() - 1);
        exit(1);
    }

    let command = &args[1];
    let filename = &args[2];

    let mut file = File::open(filename).unwrap_or_else(|why| {
        println!("Cannot open file {}: {}", filename, why);
        exit(1);
    });

    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap_or_else(|why| {
        println!("Cannot read file {}: {}", filename, why);
        exit(1);
    });

    exit(run(&command, &data[..]));
}
