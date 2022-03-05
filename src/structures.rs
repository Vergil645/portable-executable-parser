#![allow(dead_code)]

use crate::utils::*;

#[derive(Debug)]
pub struct PortableExecutable<'a> {
    raw_data: &'a [u8],

    coff_header: CoffHeader,
    optional_header: OptionalHeader,
    section_headers: Vec<SectionHeader>,

    export_table: Option<ExportTable>,
    import_table: Option<ImportTable>,
}

impl<'a> PortableExecutable<'a> {
    const E_LFANEW_OFFSET: usize = 0x3C;
    const NT_SIGNATURE: u32 = 0x50450000;

    fn is_correct_pe(data: &[u8]) -> Option<bool> {
        let e_lfanew = from_le_bytes::<i32, 4>(right_slice(data, Self::E_LFANEW_OFFSET)?)? as usize;
        let signature = from_be_bytes::<u32, 4>(right_slice(data, e_lfanew)?)?;
        Some(signature == Self::NT_SIGNATURE)
    }

    pub fn create(data: &'a [u8]) -> Option<Self> {
        if let Some(true) = Self::is_correct_pe(data) {
            let e_lfanew =
                from_le_bytes::<i32, 4>(right_slice(data, Self::E_LFANEW_OFFSET)?)? as usize;

            let raw_data = data;
            let mut data = right_slice(data, e_lfanew + 4)?;

            let coff_header = Self::create_coff_header(&mut data)?;
            let optional_header = Self::create_optional_header(&mut data)?;
            let mut section_headers = Vec::new();
            for _ in 0..coff_header.number_of_sections {
                section_headers.push(Self::create_section_header(&mut data)?);
            }

            let mut portable_executable = PortableExecutable {
                raw_data,

                coff_header,
                optional_header,
                section_headers,

                export_table: None,
                import_table: None,
            };

            portable_executable.export_table = portable_executable.create_export_table();
            portable_executable.import_table = portable_executable.create_import_table();

            Some(portable_executable)
        } else {
            None
        }
    }

    fn create_coff_header(data_ref: &mut &[u8]) -> Option<CoffHeader> {
        let (header_data, new_data) = split_at(data_ref, CoffHeader::SIZE)?;
        *data_ref = new_data;
        CoffHeader::create(header_data)
    }

    fn create_optional_header(data_ref: &mut &[u8]) -> Option<OptionalHeader> {
        let (header_data, new_data) = split_at(data_ref, OptionalHeader::SIZE)?;
        *data_ref = new_data;
        OptionalHeader::create(header_data)
    }

    fn create_section_header(data_ref: &mut &[u8]) -> Option<SectionHeader> {
        let (header_data, new_data) = split_at(data_ref, SectionHeader::SIZE)?;
        *data_ref = new_data;
        SectionHeader::create(header_data)
    }

    fn create_export_table(&mut self) -> Option<ExportTable> {
        let mut export_table = ExportTable { names: Vec::new() };

        let export_table_rva = self.optional_header.data_directories[0].rva;
        if export_table_rva == 0 && self.optional_header.data_directories[0].size == 0 {
            return None;
        }
        let export_table_raw = self.raw_from_rva(export_table_rva) as usize;

        let export_table_descriptor =
            ExportTableDescriptor::create(&self.raw_data[export_table_raw..])?;

        let names_raw = self.raw_from_rva(export_table_descriptor.names_rva) as usize;
        let mut data = &self.raw_data[names_raw..];
        for _ in 0..export_table_descriptor.number_of_names {
            let (export_name_descriptor_data, new_data) =
                split_at(data, ExportNameDescriptor::SIZE)?;
            data = new_data;

            let export_name_descriptor = ExportNameDescriptor::create(export_name_descriptor_data)?;
            let export_name_raw = self.raw_from_rva(export_name_descriptor.name_rva);
            export_table
                .names
                .push(self.string_from_raw(export_name_raw));
        }

        Some(export_table)
    }

    fn create_import_table(&mut self) -> Option<ImportTable> {
        let mut import_table = ImportTable {
            entries: Vec::new(),
        };

        let import_table_rva = self.optional_header.data_directories[1].rva;
        let import_table_raw = self.raw_from_rva(import_table_rva) as usize;

        let mut data = &self.raw_data[import_table_raw..];
        loop {
            let (import_descriptor_data, new_data) = split_at(data, ImportDescriptor::SIZE)?;
            data = new_data;
            if import_descriptor_data.iter().all(|&b| b == 0) {
                break;
            }
            let import_descriptor = ImportDescriptor::create(import_descriptor_data)?;
            import_table
                .entries
                .push(self.create_import_table_entry(&import_descriptor)?);
        }

        Some(import_table)
    }

    fn create_import_table_entry(&self, descriptor: &ImportDescriptor) -> Option<ImportTableEntry> {
        let mut import_table_entry = ImportTableEntry {
            lookup_table: LookupTable {
                entries: Vec::new(),
            },
            name: String::from("kek"),
        };

        let lookup_table_raw = self.raw_from_rva(descriptor.lookup_table_rva) as usize;

        let mut data = &self.raw_data[lookup_table_raw..];
        loop {
            let (lookup_descriptor_data, new_data) = split_at(data, LookupDescriptor::SIZE)?;
            data = new_data;
            if lookup_descriptor_data.iter().all(|&b| b == 0) {
                break;
            }
            let lookup_descriptor = LookupDescriptor::create(lookup_descriptor_data)?;
            if lookup_descriptor.import_type != 0 {
                continue;
            }

            let import_name_rwa = self.raw_from_rva(lookup_descriptor.name_rva);
            let import_name = self.string_from_raw(import_name_rwa + 2);
            let lookup_table_entry = LookupTableEntry { name: import_name };
            import_table_entry
                .lookup_table
                .entries
                .push(lookup_table_entry);
        }

        let name_raw = self.raw_from_rva(descriptor.name_rva);
        let name = self.string_from_raw(name_raw);

        import_table_entry.name = name;
        Some(import_table_entry)
    }

    fn raw_from_rva(&self, rva: u32) -> u32 {
        for section in &self.section_headers {
            if section.rva <= rva && rva < section.rva + section.virtual_size {
                return section.raw + rva - section.rva;
            }
        }
        panic!("raw_from_rva");
    }

    pub fn get_export_table(&self) -> Option<&ExportTable> {
        self.export_table.as_ref()
    }

    pub fn get_import_table(&self) -> Option<&ImportTable> {
        self.import_table.as_ref()
    }

    fn string_from_raw(&self, raw: u32) -> String {
        let raw = raw as usize;
        let mut res = String::new();
        let mut i = 0;

        while self.raw_data[raw + i] != ('\0' as u8) {
            res.push(self.raw_data[raw + i] as char);
            i += 1;
        }

        res
    }
}

#[derive(Debug)]
struct CoffHeader {
    number_of_sections: u16,
}

impl CoffHeader {
    const NUMBER_OF_SECTIONS_OFFSET: usize = 0x2;
}

impl CoffHeader {
    const SIZE: usize = 20;

    fn create(data: &[u8]) -> Option<Self> {
        Some(CoffHeader {
            number_of_sections: from_le_bytes::<u16, 2>(right_slice(
                data,
                Self::NUMBER_OF_SECTIONS_OFFSET,
            )?)?,
        })
    }
}

#[derive(Debug)]
struct OptionalHeader {
    data_directories: Vec<DataDirectory>,
}

impl OptionalHeader {
    const DIR_ENTRIES_COUNT: usize = 16;
    const DIRS_OFFSET: usize = 0x70;
}

impl OptionalHeader {
    const SIZE: usize = 240;

    fn create(data: &[u8]) -> Option<Self> {
        let mut data_directories = Vec::new();
        for i in 0..Self::DIR_ENTRIES_COUNT {
            data_directories.push(DataDirectory::create(right_slice(
                data,
                Self::DIRS_OFFSET + (i << 3),
            )?)?);
        }
        Some(OptionalHeader { data_directories })
    }
}

#[derive(Debug)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

impl DataDirectory {
    fn create(data: &[u8]) -> Option<Self> {
        Some(DataDirectory {
            rva: from_le_bytes::<u32, 4>(data)?,
            size: from_le_bytes::<u32, 4>(right_slice(data, 4)?)?,
        })
    }
}

#[derive(Debug)]
struct SectionHeader {
    virtual_size: u32,
    rva: u32,
    raw: u32,
}

impl SectionHeader {
    const VIRTUAL_ADDRESS_OFFSET: usize = 0x8;
    const RVA_OFFSET: usize = 0xC;
    const RAW_OFFSET: usize = 0x14;
}

impl SectionHeader {
    const SIZE: usize = 40;

    fn create(data: &[u8]) -> Option<Self> {
        Some(SectionHeader {
            virtual_size: from_le_bytes::<u32, 4>(right_slice(
                data,
                Self::VIRTUAL_ADDRESS_OFFSET,
            )?)?,
            rva: from_le_bytes::<u32, 4>(right_slice(data, Self::RVA_OFFSET)?)?,
            raw: from_le_bytes::<u32, 4>(right_slice(data, Self::RAW_OFFSET)?)?,
        })
    }
}

#[derive(Debug)]
struct ExportTableDescriptor {
    number_of_names: u32,
    names_rva: u32,
}

impl ExportTableDescriptor {
    const SIZE: usize = 40;
    const NUMBER_OF_NAMES_OFFSET: usize = 24;
    const NAMES_RVA_OFFSET: usize = 32;

    fn create(data: &[u8]) -> Option<Self> {
        let number_of_names =
            from_le_bytes::<u32, 4>(right_slice(data, Self::NUMBER_OF_NAMES_OFFSET)?)?;
        let names_rva = from_le_bytes::<u32, 4>(right_slice(data, Self::NAMES_RVA_OFFSET)?)?;

        Some(ExportTableDescriptor {
            number_of_names,
            names_rva,
        })
    }
}

#[derive(Debug)]
pub struct ExportTable {
    pub names: Vec<String>,
}

#[derive(Debug)]
struct ExportNameDescriptor {
    name_rva: u32,
}

impl ExportNameDescriptor {
    const SIZE: usize = 4;

    fn create(data: &[u8]) -> Option<Self> {
        Some(ExportNameDescriptor {
            name_rva: from_le_bytes::<u32, 4>(data)?,
        })
    }
}

#[derive(Debug)]
struct ImportDescriptor {
    lookup_table_rva: u32,
    name_rva: u32,
}

impl ImportDescriptor {
    const SIZE: usize = 20;
    const LOOKUP_TABLE_RVA_OFFSET: usize = 0;
    const NAME_OFFSET: usize = 0xC;

    fn create(data: &[u8]) -> Option<Self> {
        Some(ImportDescriptor {
            lookup_table_rva: from_le_bytes::<u32, 4>(right_slice(
                data,
                Self::LOOKUP_TABLE_RVA_OFFSET,
            )?)?,
            name_rva: from_le_bytes::<u32, 4>(right_slice(data, Self::NAME_OFFSET)?)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ImportTable {
    pub entries: Vec<ImportTableEntry>,
}

#[derive(Debug, Clone)]
pub struct ImportTableEntry {
    pub lookup_table: LookupTable,
    pub name: String,
}

#[derive(Debug)]
struct LookupDescriptor {
    import_type: u8,
    name_rva: u32,
}

impl LookupDescriptor {
    const SIZE: usize = 8;

    fn create(data: &[u8]) -> Option<Self> {
        let number = from_le_bytes::<u64, 8>(data)?;
        let import_type = ((number >> 63) & 1) as u8;

        let name_rva = from_le_bytes::<u32, 4>(data)?;

        Some(LookupDescriptor {
            import_type,
            name_rva,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LookupTable {
    pub entries: Vec<LookupTableEntry>,
}

#[derive(Debug, Clone)]
pub struct LookupTableEntry {
    pub name: String,
}
