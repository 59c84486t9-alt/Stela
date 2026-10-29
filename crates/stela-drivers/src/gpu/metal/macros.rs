//! Declarations for ABI enumerations and option sets with fixed raw values.
//!
//! Metal and Vulkan values cross process and library boundaries as plain
//! integers. These macros keep each declaration's variants, raw values and
//! decoder in one list, so a value can never decode to a different variant
//! than the one that encodes it.

/// A closed enumeration with fixed raw values. Decoding refuses any value the
/// list does not name; `ALL` lists the variants in declaration order.
macro_rules! raw_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident: $raw:ty {
            $($(#[$variant_meta:meta])* $variant:ident = $value:expr,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        #[repr($raw)]
        $vis enum $name {
            $($(#[$variant_meta])* $variant = $value,)+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            pub const fn raw(self) -> $raw {
                self as $raw
            }

            pub fn from_raw(raw: $raw) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.raw() == raw)
            }
        }
    };
}

/// A bit set with named flags. `from_bits` refuses bits outside `KNOWN`;
/// the set operations never create unnamed bits.
macro_rules! option_set {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident: $raw:ty {
            $($(#[$flag_meta:meta])* const $flag:ident = $value:expr;)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
        $vis struct $name($raw);

        #[allow(dead_code)]
        impl $name {
            $($(#[$flag_meta])* pub const $flag: Self = Self($value);)*
            pub const EMPTY: Self = Self(0);
            pub const KNOWN: Self = Self(0 $(| $value)*);

            pub const fn bits(self) -> $raw {
                self.0
            }

            pub const fn from_bits(bits: $raw) -> Option<Self> {
                if bits & !Self::KNOWN.0 == 0 { Some(Self(bits)) } else { None }
            }

            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }

            pub const fn contains(self, other: Self) -> bool {
                self.0 & other.0 == other.0
            }

            pub const fn intersects(self, other: Self) -> bool {
                self.0 & other.0 != 0
            }

            pub const fn union(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }

            pub const fn intersection(self, other: Self) -> Self {
                Self(self.0 & other.0)
            }

            pub const fn difference(self, other: Self) -> Self {
                Self(self.0 & !other.0)
            }

            /// Includes `other` when `condition` holds.
            pub const fn with(self, other: Self, condition: bool) -> Self {
                if condition { self.union(other) } else { self }
            }
        }

        impl core::ops::BitOr for $name {
            type Output = Self;

            fn bitor(self, other: Self) -> Self {
                self.union(other)
            }
        }

        impl core::ops::BitOrAssign for $name {
            fn bitor_assign(&mut self, other: Self) {
                *self = self.union(other);
            }
        }

        impl core::ops::BitAnd for $name {
            type Output = Self;

            fn bitand(self, other: Self) -> Self {
                self.intersection(other)
            }
        }
    };
}
