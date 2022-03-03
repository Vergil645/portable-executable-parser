mod structures;
mod utils;

use crate::structures::*;

pub fn is_pe(data: &[u8]) -> Result<String, String> {
    if let Some(_) = PortableExecutable::create(data) {
        Ok(String::from("PE"))
    } else {
        Err(String::from("Not PE"))
    }
}

pub fn import_functions(data: &[u8]) -> Result<String, String> {
    match PortableExecutable::create(data) {
        Some(portable_executable) => {
            let import_table_ref = portable_executable.get_import_table();
            let mut info = Vec::new();
            for entry in &import_table_ref.entries {
                info.push(format!("{}", entry.name));
                for lookup_entry in &entry.lookup_table.entries {
                    info.push(format!("    {}", lookup_entry.name));
                }
            }
            Ok(info.join("\n"))
        },
        None => Err(String::from("Not PE")),
    }
}

pub fn export_functions(data: &[u8]) -> Result<String, String> {
    match PortableExecutable::create(data) {
        Some(portable_executable) => {
            let export_table = portable_executable.get_export_table();
            Ok(export_table.names.join("\n"))
        },
        None => Err(String::from("Not PE")),
    }
}
