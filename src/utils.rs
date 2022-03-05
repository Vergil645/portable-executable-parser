#![allow(dead_code)]

use std::convert::TryInto;
use std::mem::size_of;

pub trait FromLe<const SIZE_OF: usize> {
    fn from_le_bytes(bytes: [u8; SIZE_OF]) -> Self;
}

pub trait FromBe<const SIZE_OF: usize> {
    fn from_be_bytes(bytes: [u8; SIZE_OF]) -> Self;
}

pub fn split_at<T>(slice: &[T], mid: usize) -> Option<(&[T], &[T])> {
    if mid <= slice.len() {
        Some(slice.split_at(mid))
    } else {
        None
    }
}

pub fn left_slice<T>(slice: &[T], end: usize) -> Option<&[T]> {
    if end <= slice.len() {
        Some(&slice[..end])
    } else {
        None
    }
}

pub fn right_slice<T>(slice: &[T], begin: usize) -> Option<&[T]> {
    if begin <= slice.len() {
        Some(&slice[begin..])
    } else {
        None
    }
}

pub fn from_le_bytes<T, const SIZE_OF: usize>(bytes_ref: &[u8]) -> Option<T>
where
    T: FromLe<SIZE_OF>,
{
    match left_slice(bytes_ref, size_of::<T>())?.try_into() {
        Ok(bytes) => Some(T::from_le_bytes(bytes)),
        Err(_) => None,
    }
}

pub fn from_be_bytes<T, const SIZE_OF: usize>(bytes_ref: &[u8]) -> Option<T>
where
    T: FromBe<SIZE_OF>,
{
    match left_slice(bytes_ref, size_of::<T>())?.try_into() {
        Ok(bytes) => Some(T::from_be_bytes(bytes)),
        Err(_) => None,
    }
}

// Implementations of FromLe and FromBe for some primitive types

impl FromLe<2> for u16 {
    fn from_le_bytes(bytes: [u8; size_of::<u16>()]) -> Self {
        u16::from_le_bytes(bytes)
    }
}

impl FromLe<4> for u32 {
    fn from_le_bytes(bytes: [u8; size_of::<u32>()]) -> Self {
        u32::from_le_bytes(bytes)
    }
}

impl FromLe<4> for i32 {
    fn from_le_bytes(bytes: [u8; size_of::<i32>()]) -> Self {
        i32::from_le_bytes(bytes)
    }
}

impl FromLe<8> for u64 {
    fn from_le_bytes(bytes: [u8; size_of::<u64>()]) -> Self {
        u64::from_le_bytes(bytes)
    }
}

impl FromBe<4> for u32 {
    fn from_be_bytes(bytes: [u8; size_of::<u32>()]) -> Self {
        u32::from_be_bytes(bytes)
    }
}
