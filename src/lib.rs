mod structures;
mod utils;

use crate::structures::*;

pub fn is_pe(data: &[u8]) -> i32 {
    if let Some(_) = PortableExecutable::create(data) {
        println!("PE");
        0
    } else {
        println!("Not PE");
        1
    }
}

pub fn import_functions(data: &[u8]) -> i32 {
    match PortableExecutable::create(data) {
        Some(portable_executable) => {
            let import_table_ref = portable_executable.get_import_table();
            let mut info = String::new();
            for entry in &import_table_ref.entries {
                info.push_str(&format!("{}\n", entry.name));
                for lookup_entry in &entry.lookup_table.entries {
                    info.push_str(&format!("    {}\n", lookup_entry.name));
                }
            }
            print!("{}", info);
            0
        },
        None => {
            println!("Not PE");
            1
        }
    }
}

pub fn export_functions(data: &[u8]) -> i32 {
    match PortableExecutable::create(data) {
        Some(portable_executable) => {
            let export_table = portable_executable.get_export_table();
            for name in &export_table.names {
                println!("{}", name);
            }
            0
        },
        None => {
            println!("Not PE");
            1
        }
    }
}
