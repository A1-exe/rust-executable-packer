// in `delf/src/lib.rs`

mod parse;

use std::convert::TryFrom;
use derive_try_from_primitive::TryFromPrimitive;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Type {
  None = 0x0,
  Rel = 0x1,
  Exec = 0x2,
  Dyn = 0x3,
  Core = 0x4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u16)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3e,
}

impl_parse_for_enum!(Type, le_u16);
impl_parse_for_enum!(Machine, le_u16);
pub struct HexDump<'a>(&'a [u8]);

use std::fmt;
impl<'a> fmt::Debug for HexDump<'a> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    for &x in self.0.iter().take(20) {
      write!(f, "{:02x} ", x)?;
    }
    Ok(())
  }
}

#[derive(Debug)]
pub struct File {
  pub r#type: Type,
  pub machine: Machine,
}

impl File {
  const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

  pub fn parse(i: parse::Input) -> parse::Result<Self> {
    use nom::{
      bytes::complete::{tag, take},
      error::context,
      sequence::tuple,
      combinator::map,
      number::complete::le_u16,
    };
    
    let (i, _) = tuple((
      // -------
      context("Magic", tag(Self::MAGIC)),
      context("Class", tag(&[0x2])),
      context("Endianness", tag(&[0x1])),
      context("Version", tag(&[0x1])),
      context("OS ABI", nom::branch::alt((tag(&[0x0]), tag(&[0x3])))),
      // -------
      context("Padding", take(8_usize)),
    ))(i)?;

    let (i, (r#type, machine)) = tuple((Type::parse, Machine::parse))(i)?;

    Ok((i, Self { r#type, machine }))
  }

  pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
    match Self::parse(i) {
      Ok((_, file)) => Some(file),
      Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
        eprintln!("Parsing failed:");
        for (input, err) in err.errors {
          use nom::Offset;
          let offset = i.offset(input);
          eprintln!("{:?} at position {}:", err, offset);
          eprintln!("{:>08x}: {:?}", offset, HexDump(input));
        }
        None
      },
      Err(_) => panic!("unexpected nom error"),
    }
  }
}


#[cfg(test)]
mod tests {
  use super::Machine;

  #[test]
  fn try_enums() {
    assert_eq!(Machine::X86_64 as u16, 0x3E);
    assert_eq!(Machine::try_from(0x3E), Ok(Machine::X86_64));
    assert_eq!(Machine::try_from(0xFA), Err(0xFA));
  }
}