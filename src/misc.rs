// Axel '0vercl0k' Souchet - February 23 2024
//! This module contains the implementation of a bunch of misc utility functions
//! that didn't really fit anywhere else.

use std::mem::transmute;

/// A relative address.
pub(crate) type Rva = u32;

/// Convert an `u64` into an hex string.
///
/// Highly inspired by 'Fast unsigned integer to hex string' by Johnny Lee:
///   - <https://johnnylee-sde.github.io/Fast-unsigned-integer-to-hex-string/>
pub(crate) fn fast_hex64(buffer: &mut [u8; 16], u: u64) -> &[u8] {
    let mut x = u128::from(u);

    // Arrange each digit into their own byte. Each byte will become the ascii
    // character representing its digit. For example, we want to arrange:
    //   - `0x00000000_00000000_DEADBEEF_BAADC0DE` into
    //   - `0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E`.
    //
    // Here's a step by step using `0xDEADBEEF_BAADC0DE`:
    //   1. `x = 0x00000000_DEADBEEF_00000000_BAADC0DE`
    //   2. `x = 0xDEAD0000_BEEF0000_BAAD0000_C0DE0000`
    //   3. `x = 0x00DE00AD_00BE00EF_00BA00AD_00C000DE`
    //   4. `x = 0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E`
    //
    // Let's start the dance..
    x = (x & 0xFFFF_FFFF_0000_0000) << 32 | x;
    x = ((x & 0xFFFF_0000_0000_0000_FFFF_0000) << 32) | ((x & 0xFFFF_0000_0000_0000_FFFF) << 16);
    x = ((x & 0x00FF_0000_00FF_0000_00FF_0000_00FF_0000) >> 16)
        | ((x & 0xFF00_0000_FF00_0000_FF00_0000_FF00_0000) >> 8);
    x = ((x & 0x00F0_00F0_00F0_00F0_00F0_00F0_00F0_00F0) << 4)
        | (x & 0x000F_000F_000F_000F_000F_000F_000F_000F);

    // This creates a mask where there'll be a 0x01 byte for each digit that is
    // alpha. For example, for `0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E` we want:
    // `0x01010101_01010101_01010101_01000101`. The trick is to add 0x06 to each
    // byte; if the digit is 0x0A..0x0F, adding 0x06 will give 0x10..0x15 (notice
    // the leading '1'). Note that we need to ADD, not an OR :). At this point,
    // right shifting by 4 bits means to position that leading '1' in the lower
    // nibble which is then 'grabbed' via the masking with 0x01..
    let mask = ((x + 0x0606_0606_0606_0606_0606_0606_0606_0606) >> 4)
        & 0x0101_0101_0101_0101_0101_0101_0101_0101;

    // Turn each digit into their ASCII equivalent by setting the high nibble of
    // each byte to 0x3. `0x0D0E0A0D_0B0E0E0F_0B0A0A0D_0C000D0E` becomes
    // `0x3D3E3A3D_3B3E3E3F_3B3A3A3D_3C303D3E`.
    x |= 0x3030_3030_3030_3030_3030_3030_3030_3030;

    // The last step is to adjust the ASCII byte for every digit that was in
    // 0xA..0xF. We basically add to each of those bytes `0x27` to make them lower
    // case alpha ASCII.
    // For example:
    //   - `0x01010101_01010101_01010101_01000101 * 0x27 =
    //     0x27272727_27272727_27272727_27002727`
    //   - `0x3D3E3A3D_3B3E3E3F_3B3A3A3D_3C303D3E +
    //     0x27272727_27272727_27272727_27002727` =
    //     `0x64656164_62656566_62616164_63306465`
    //
    // Why `0x27`? Well, if we have the digit 'a', we end up with `0x3a`. ASCII
    // character for 'a' is `0x61`, so `0x61 - 0x3a = 0x27`.
    x += 0x27 * mask;

    // Transform the integer into a slice of bytes.
    buffer.copy_from_slice(&x.to_be_bytes());

    // We're done!
    buffer
}

/// Convert an `u32` into an hex string.
///
/// Highly inspired by 'Fast unsigned integer to hex string' by Johnny Lee:
///   - <https://johnnylee-sde.github.io/Fast-unsigned-integer-to-hex-string/>
///
/// Adapted to not bother shuffling the bytes in little endian; we simply read
/// the final integer as big endian.
pub(crate) fn fast_hex32(buffer: &mut [u8; 8], u: u32) -> &[u8] {
    let mut x = u64::from(u);

    // Here's a step by step using `0xDEADBEEF`:
    //   1. `x = 0x0000DEAD_0000BEEF`
    //   2. `x = 0xDE00AD00_BE00EF00`
    //   3. `x = 0x0D0E0A0D_0B0E0E0F`
    x = (x & 0xFFFF_0000) << 16 | x;
    x = ((x & 0x0000_FF00_0000_FF00) << 16) | ((x & 0x0000_00FF_0000_00FF) << 8);
    x = ((x & 0xF000_F000_F000_F000) >> 4) | ((x & 0x0F00_0F00_0F00_0F00) >> 8);

    let mask = ((x + 0x0606_0606_0606_0606) >> 4) & 0x0101_0101_0101_0101;
    x |= 0x3030_3030_3030_3030;
    x += 0x27 * mask;

    buffer.copy_from_slice(&x.to_be_bytes());

    buffer
}

#[derive(Debug, PartialEq)]
pub(crate) struct ParsedFullSymbolName<'s> {
    pub module_name: &'s str,
    pub function_name: &'s str,
    pub offset: u64,
}

/// Parse `mod!func+0xoffset`.
pub(crate) fn parse_full_name(full: &str) -> Option<ParsedFullSymbolName<'_>> {
    let (module_name, rest) = full.split_once('!')?;
    if rest.contains('!') {
        return None;
    }

    let (function_name, offset) = match rest.split_once('+') {
        Some((function_name, offset)) => {
            if !offset.starts_with("0x") {
                return None;
            }

            (
                function_name,
                u64::from_str_radix(offset.trim_start_matches("0x"), 16).ok()?,
            )
        }
        None => (rest, 0),
    };

    Some(ParsedFullSymbolName {
        module_name,
        function_name,
        offset,
    })
}

/// Extend the lifetime of a string slice to static; be VERY careful with this.
pub(crate) unsafe fn elyxir_of_life<'s>(s: &'s str) -> &'static str {
    unsafe { transmute::<&'s str, &'static str>(s) }
}

#[cfg(test)]
mod tests {
    use super::{fast_hex32, fast_hex64};
    use crate::misc::{ParsedFullSymbolName, parse_full_name};

    #[test]
    fn hex32() {
        let mut buffer = [0; 8];
        let out = fast_hex32(&mut buffer, 0xdead_beef);
        assert_eq!(out, b"deadbeef");
        let out = fast_hex32(&mut buffer, 0xdead);
        assert_eq!(out, b"0000dead");
        let out = fast_hex32(&mut buffer, 0x0);
        assert_eq!(out, b"00000000");
    }

    #[test]
    fn hex64() {
        let mut buffer = [0; 16];
        let out = fast_hex64(&mut buffer, 0xdead_beef_baad_c0de);
        assert_eq!(out, b"deadbeefbaadc0de");
        let out = fast_hex64(&mut buffer, 0xdead_beef);
        assert_eq!(out, b"00000000deadbeef");
        let out = fast_hex64(&mut buffer, 0x0);
        assert_eq!(out, b"0000000000000000");
    }

    #[test]
    fn parse() {
        assert_eq!(
            parse_full_name("yo.dll!func").unwrap(),
            ParsedFullSymbolName {
                module_name: "yo.dll",
                function_name: "func",
                offset: 0
            }
        );

        assert_eq!(
            parse_full_name("yo!func+0x1337").unwrap(),
            ParsedFullSymbolName {
                module_name: "yo",
                function_name: "func",
                offset: 0x1337
            }
        );

        assert!(parse_full_name("yo!!func").is_none());
        assert!(parse_full_name("yo!func+1337").is_none());

        assert_eq!(
            parse_full_name("foo.dll!Microsoft::WRL::Details::ModuleBase::GetMidEntryPointer+0x0")
                .unwrap(),
            ParsedFullSymbolName {
                module_name: "foo.dll",
                function_name: "Microsoft::WRL::Details::ModuleBase::GetMidEntryPointer",
                offset: 0
            }
        );
    }
}
