// in `delf/src/lib.rs`

mod parse;

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

impl Type {
  fn to_u16(&self) -> u16 {
    match self {
      Self::None => 0,
      Self::Rel => 1,
      Self::Exec => 2,
      Self::Dyn => 3,
      Self::Core => 4,
    }
  }

  pub fn from_u16(x: u16) -> Option<Self> {
    match x {
      0 => Some(Self::None),
      1 => Some(Self::Rel),
      2 => Some(Self::Exec),
      3 => Some(Self::Dyn),
      4 => Some(Self::Core),
      _ => None,
    }
  }
}

#[derive(Debug)]
pub struct File {

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

    Ok((i, Self {}))
  }
}


#[cfg(test)]
mod tests {
  #[test]
  fn type_to_u16(){
    assert_eq!(super::Type::Dyn as u16, 0x3);
  }
}