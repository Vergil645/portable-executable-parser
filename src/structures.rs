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

    fn is_correct_pe(data: &[u8]) -> bool {
        if Self::E_LFANEW_OFFSET + 4 > data.len() {
            return false;
        }

        let e_lfanew = i32_from_le_bytes(&data[Self::E_LFANEW_OFFSET..]) as usize;
        if e_lfanew + 4 > data.len() {
            return false;
        }

        let signature = u32_from_be_bytes(&data[e_lfanew..]);
        signature == Self::NT_SIGNATURE
    }

    pub fn create(data: &'a [u8]) -> Option<Self> {
        if Self::is_correct_pe(data) {
            let e_lfanew = i32_from_le_bytes(&data[Self::E_LFANEW_OFFSET..]) as usize;

            let raw_data = data;
            let mut data = &data[e_lfanew + 4..];

            let coff_header: CoffHeader = Self::create_header(&mut data);
            let optional_header = Self::create_header(&mut data);
            let section_headers = (0..coff_header.number_of_sections)
                .map(|_| Self::create_header(&mut data))
                .collect();

            let mut portable_executable = PortableExecutable {
                raw_data,

                coff_header,
                optional_header,
                section_headers,

                export_table: None,
                import_table: None,
            };

            portable_executable.create_export_table();
            portable_executable.create_import_table();

            Some(portable_executable)
        } else {
            None
        }
    }

    fn create_header<T: Header>(data_ref: &mut &[u8]) -> T {
        let (header_data, new_data) = data_ref.split_at(T::SIZE);
        *data_ref = new_data;
        T::create(header_data)
    }

    fn create_export_table(&mut self) {
        let mut export_table = ExportTable { names: Vec::new() };

        let export_table_rva = self.optional_header.data_directories[0].rva;
        if export_table_rva == 0 && self.optional_header.data_directories[0].size == 0 {
            return;
        }
        let export_table_raw = self.raw_from_rva(export_table_rva) as usize;

        let export_table_descriptor =
            ExportTableDescriptor::create(&self.raw_data[export_table_raw..]);

        let names_raw = self.raw_from_rva(export_table_descriptor.names_rva) as usize;
        let mut data = &self.raw_data[names_raw..];
        for _ in 0..export_table_descriptor.number_of_names {
            let (export_name_descriptor_data, new_data) = data.split_at(ExportNameDescriptor::SIZE);
            data = new_data;

            let export_name_descriptor = ExportNameDescriptor::create(export_name_descriptor_data);
            let export_name_raw = self.raw_from_rva(export_name_descriptor.name_rva);
            export_table
                .names
                .push(self.string_from_raw(export_name_raw));
        }

        self.export_table = Some(export_table);
    }

    fn create_import_table(&mut self) {
        let mut import_table = ImportTable {
            entries: Vec::new(),
        };

        let import_table_rva = self.optional_header.data_directories[1].rva;
        let import_table_raw = self.raw_from_rva(import_table_rva) as usize;

        let mut data = &self.raw_data[import_table_raw..];
        loop {
            let (import_descriptor_data, new_data) = data.split_at(ImportDescriptor::SIZE);
            data = new_data;
            if import_descriptor_data.iter().all(|&b| b == 0) {
                break;
            }
            let import_descriptor = ImportDescriptor::create(import_descriptor_data);
            import_table
                .entries
                .push(self.create_import_table_entry(&import_descriptor));
        }

        self.import_table = Some(import_table);
    }

    fn create_import_table_entry(&self, descriptor: &ImportDescriptor) -> ImportTableEntry {
        let mut import_table_entry = ImportTableEntry {
            lookup_table: LookupTable {
                entries: Vec::new(),
            },
            name: String::from("kek"),
        };

        let lookup_table_raw = self.raw_from_rva(descriptor.lookup_table_rva) as usize;

        let mut data = &self.raw_data[lookup_table_raw..];
        loop {
            let (lookup_descriptor_data, new_data) = data.split_at(LookupDescriptor::SIZE);
            data = new_data;
            if lookup_descriptor_data.iter().all(|&b| b == 0) {
                break;
            }
            let lookup_descriptor = LookupDescriptor::create(lookup_descriptor_data);
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
        import_table_entry
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

trait Header {
    const SIZE: usize;

    fn create(data: &[u8]) -> Self;
}

#[derive(Debug)]
struct CoffHeader {
    number_of_sections: u16,
}

impl CoffHeader {
    const NUMBER_OF_SECTIONS_OFFSET: usize = 0x2;
}

impl Header for CoffHeader {
    const SIZE: usize = 20;

    fn create(data: &[u8]) -> Self {
        CoffHeader {
            number_of_sections: u16_from_le_bytes(&data[Self::NUMBER_OF_SECTIONS_OFFSET..]),
        }
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

impl Header for OptionalHeader {
    const SIZE: usize = 240;

    fn create(data: &[u8]) -> Self {
        OptionalHeader {
            data_directories: (0..Self::DIR_ENTRIES_COUNT)
                .map(|i| DataDirectory::create(&data[(Self::DIRS_OFFSET + (i << 3))..]))
                .collect(),
        }
    }
}

#[derive(Debug)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

impl DataDirectory {
    fn create(data: &[u8]) -> Self {
        DataDirectory {
            rva: u32_from_le_bytes(data),
            size: u32_from_le_bytes(&data[4..]),
        }
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

impl Header for SectionHeader {
    const SIZE: usize = 40;

    fn create(data: &[u8]) -> Self {
        SectionHeader {
            virtual_size: u32_from_le_bytes(&data[Self::VIRTUAL_ADDRESS_OFFSET..]),
            rva: u32_from_le_bytes(&data[Self::RVA_OFFSET..]),
            raw: u32_from_le_bytes(&data[Self::RAW_OFFSET..]),
        }
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

    fn create(data: &[u8]) -> Self {
        let number_of_names = u32_from_le_bytes(&data[Self::NUMBER_OF_NAMES_OFFSET..]);
        let names_rva = u32_from_le_bytes(&data[Self::NAMES_RVA_OFFSET..]);

        ExportTableDescriptor {
            number_of_names,
            names_rva,
        }
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

    fn create(data: &[u8]) -> Self {
        ExportNameDescriptor {
            name_rva: u32_from_le_bytes(data),
        }
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

    fn create(data: &[u8]) -> Self {
        ImportDescriptor {
            lookup_table_rva: u32_from_le_bytes(&data[Self::LOOKUP_TABLE_RVA_OFFSET..]),
            name_rva: u32_from_le_bytes(&data[Self::NAME_OFFSET..]),
        }
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

    fn create(data: &[u8]) -> Self {
        let number = u64_from_le_bytes(data);
        let import_type = ((number >> 63) & 1) as u8;

        let name_rva = u32_from_le_bytes(data);

        LookupDescriptor {
            import_type,
            name_rva,
        }
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
