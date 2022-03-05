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
            match portable_executable.get_import_table() {
                Some(import_table_ref) => {
                    let mut info = Vec::new();
                    for entry in &import_table_ref.entries {
                        info.push(format!("{}", entry.name));
                        for lookup_entry in &entry.lookup_table.entries {
                            info.push(format!("    {}", lookup_entry.name));
                        }
                    }
                    Ok(info.join("\n"))
                },
                None => Ok(String::from("Don't import any functions"))
            }
        },
        None => Err(String::from("Not PE")),
    }
}

pub fn export_functions(data: &[u8]) -> Result<String, String> {
    match PortableExecutable::create(data) {
        Some(portable_executable) => {
            match portable_executable.get_export_table() {
                Some(export_table_ref) => Ok(export_table_ref.names.join("\n")),
                None => Ok(String::from("Don't export any functions"))
            }
        },
        None => Err(String::from("Not PE")),
    }
}
