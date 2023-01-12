// in `delf/src/lib.rs`

mod parse;

use std::convert::TryFrom;
use derive_try_from_primitive::TryFromPrimitive;
use derive_more::*;

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

// "Add" and "Sub" are in `derive_more`
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// This will come in handy when serializing
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}

// This will come in handy when indexing / sub-slicing slices
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}

// This will come in handy when parsing
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::{combinator::map, number::complete::le_u64};
        map(le_u64, From::from)(i)
    }
}

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
  pub entry_point: Addr,
}

impl File {
  const MAGIC: &'static [u8] = &[0x7f, 0x45, 0x4c, 0x46];

  pub fn parse(i: parse::Input) -> parse::Result<Self> {
    use nom::{
      bytes::complete::{tag, take},
      error::context,
      sequence::tuple,
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

    // this 32-bit integer should always be set to 1 in the current
    // version of ELF, see the diagram. We don't *have* to check it,
    // but it's so easy to, let's anyway!
    use nom::{combinator::verify, number::complete::le_u32};
    let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?;
    let (i, entry_point) = Addr::parse(i)?;

    Ok((i, Self { 
      r#type,
      machine,
      entry_point
    }))
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