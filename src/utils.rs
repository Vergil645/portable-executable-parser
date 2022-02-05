#![allow(dead_code)]

use std::convert::TryInto;
use std::mem::size_of;

pub fn u16_from_le_bytes(bytes: &[u8]) -> u16 {
    u16::from_le_bytes((&bytes[..size_of::<u16>()]).try_into().unwrap())
}

pub fn u32_from_le_bytes(bytes: &[u8]) -> u32 {
    u32::from_le_bytes((&bytes[..size_of::<u32>()]).try_into().unwrap())
}

pub fn u32_from_be_bytes(bytes: &[u8]) -> u32 {
    u32::from_be_bytes((&bytes[..size_of::<u32>()]).try_into().unwrap())
}

pub fn i32_from_le_bytes(bytes: &[u8]) -> i32 {
    i32::from_le_bytes((&bytes[..size_of::<i32>()]).try_into().unwrap())
}

pub fn u64_from_le_bytes(bytes: &[u8]) -> u64 {
    u64::from_le_bytes((&bytes[..size_of::<u64>()]).try_into().unwrap())
}
