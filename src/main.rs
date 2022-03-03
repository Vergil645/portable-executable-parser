use std::env;
use std::fs::*;
use std::io::Read;
use std::process::exit;

use pe_parser::{export_functions, import_functions, is_pe};

const OK: i32 = 0;
const NOT_PE_ERROR: i32 = 1;
const ARGUMENTS_ERROR: i32 = 2;
const IO_ERROR: i32 = 3;

const COMMANDS: [(&str, fn(&[u8]) -> Result<String, String>); 3] = [
    ("is-pe", is_pe),
    ("import-functions", import_functions),
    ("export-functions", export_functions),
];

fn run(command: &str, data: &[u8]) -> Result<String, String> {
    match COMMANDS.iter().find(|(name, _)| *name == command) {
        Some(&(_, func)) => func(data),
        None => Err(format!("Cannot find a command {}!", command)),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Expected 2 arguments, found: {}", args.len() - 1);
        exit(ARGUMENTS_ERROR);
    }

    let command = &args[1];
    let filename = &args[2];

    let mut file = File::open(filename).unwrap_or_else(|why| {
        println!("Cannot open file {}: {}", filename, why);
        exit(IO_ERROR);
    });

    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap_or_else(|why| {
        println!("Cannot read file {}: {}", filename, why);
        exit(IO_ERROR);
    });

    match run(&command, &data[..]) {
        Ok(output_string) => {
            println!("{}", output_string);
            exit(OK);
        },
        Err(error_string) => {
            println!("{}", error_string);
            exit(NOT_PE_ERROR);
        },
    }
}
