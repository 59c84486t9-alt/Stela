//! The part of `std` Mesa's Rust uses, over `core` and `alloc`, for a target
//! with neither processes nor files.
//!
//! Each Mesa crate depends on this under the name `std`, so the prelude rustc
//! injects and every `std::` path in its source resolve here with no change to
//! Mesa. Its crates build as ordinary dependencies of `stela.efi`, under that
//! image's allocator and panic handler.
#![no_std]

extern crate alloc as alloc_crate;

pub use alloc_crate::{alloc, borrow, boxed, fmt, format, rc, slice, str, string, vec};
pub use core::primitive::{i128, i16, i32, i64, i8, isize, u128, u16, u32, u64, u8, usize};
pub use core::{
    any, array, ascii, assert, assert_eq, assert_ne, cell, char, clone, cmp, column, compile_error,
    concat, convert, debug_assert, debug_assert_eq, debug_assert_ne, default, f32, f64, file,
    format_args, future, hint, include, include_bytes, include_str, iter, line, marker, matches,
    mem, module_path, num, ops, option, option_env, pin, ptr, result, stringify, task, time, todo,
    unimplemented, unreachable, write, writeln,
};

pub mod collections;
pub mod env;
pub mod ffi;
pub mod fs;
pub mod hash;
pub mod io;
pub mod panic;
pub mod sync;

mod float;

pub mod os {
    pub mod raw {
        pub use core::ffi::{
            c_char, c_double, c_float, c_int, c_long, c_longlong, c_schar, c_short, c_uchar,
            c_uint, c_ulong, c_ulonglong, c_ushort, c_void,
        };
    }
}

pub mod prelude {
    pub mod rust_2021 {
        pub use crate::{eprint, eprintln, float::Float as _, print, println};
        pub use alloc_crate::{
            borrow::ToOwned,
            boxed::Box,
            format,
            string::{String, ToString},
            vec,
            vec::Vec,
        };
        pub use core::prelude::rust_2021::*;
    }
    pub use rust_2021 as v1;
}

/// One line for the host's log, as `eprint!` writes it.
#[macro_export]
macro_rules! eprint {
    ($($argument:tt)*) => { $crate::io::_log($crate::format_args!($($argument)*)) };
}

#[macro_export]
macro_rules! eprintln {
    () => { $crate::eprint!("\n") };
    ($($argument:tt)*) => {{
        $crate::eprint!($($argument)*);
        $crate::eprint!("\n");
    }};
}

#[macro_export]
macro_rules! print {
    ($($argument:tt)*) => { $crate::eprint!($($argument)*) };
}

#[macro_export]
macro_rules! println {
    ($($argument:tt)*) => { $crate::eprintln!($($argument)*) };
}
