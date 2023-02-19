// in `elk/src/main.rs`

use std::{env, error::Error, fs};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
  let input_path = env::args().nth(1).expect("usage: elk FILE");
  let input = fs::read(&input_path)?;
  
  println!("Analyzing {}...", input_path);
  let file = match delf::File::parse_or_print_error(&input[..]) {
    Some(f) => f,
    None => std::process::exit(1),
  };
  println!("{:#?}", file);

  // println!("Executing {:?}...", input_path);
  // use std::process::Command;
  // let status = Command::new(input_path).status()?;
  // if !status.success() {
  //   return Err("process did not exit successfully".into());
  // }

  println!("Disassembling {:?}...", input_path);
  let code_ph = file
      .program_headers
      .iter()
      .find(|ph| ph.mem_range().contains(&file.entry_point))
      .expect("segment with entry point not found");

  ndisasm(&code_ph.data[..], file.entry_point)?;

  println!("Mapping {:?} into memory...", input_path);

  // we'll need to hold onto our "mmap::MemoryMap", because dropping them
  // unmaps the memory
  let mut mappings = Vec::new();

  // we're only interested in "Load" segments
  for ph in file
    .program_headers
    .iter()
    .filter(|ph| ph.r#type == delf::SegmentType::Load)
  {
    let mem_range = ph.mem_range();
    println!("Mapping segments @ {:?} with {:?}", mem_range, ph.flags);
    // note: mmap-ing would fail if the segments weren't aligned on page boundaries,
    // but luckily, that is the case in the file already. That is not a coincidence.
    let len: usize = (mem_range.end - mem_range.start).into();
    // `as` is the "cast" operator, and `_` is a placeholder to force rustc
    // to infer the tpe based on other hints
    let addr: *mut u8 = mem_range.start.0 as _;
    // at first, we want the memory area to be writable, so we can copy to it
    let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;
  
    println!("Copying segment data...");
    {
      let dst = unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) };
      dst.copy_from_slice(&ph.data[..]);
    }

    println!("Adjusting memory protection...");
    // the `region` crate and our `delf` crate have two different
    // enums (and bit flags) for protection, so we need to map from
    // delf's to region's
    let mut protection = Protection::NONE;
    for flag in ph.flags.iter() {
      protection |= match flag {
        delf::SegmentFlag::Read => Protection::READ,
        delf::SegmentFlag::Write => Protection::WRITE,
        delf::SegmentFlag::Execute => Protection::EXECUTE,
      }
    }

    unsafe {
      protect(addr, len, protection)?;
    }
    mappings.push(map);
  }

  println!("Executing {:?} in memory...", input_path);
  let code = &code_ph.data[..];
  unsafe {
    protect(code.as_ptr(), code.len(), Protection::READ_WRITE_EXECUTE)?;
  }

  let entry_offset = file.entry_point - code_ph.mem_range().start;
  let entry_point = unsafe { code.as_ptr().add(entry_offset.into()) };
  println!("       code  @ {:?}", code.as_ptr());
  println!("entry offset @ {:?}", entry_offset);
  println!("entry point  @ {:?}", entry_point);
  unsafe {
      jmp(entry_point);
  }

  Ok(())
}

fn ndisasm(code: &[u8], origin: delf::Addr) -> Result<(), Box<dyn Error>> {
  use std::{
    io::Write,
    process::{Command, Stdio},
  };

  let mut child = Command::new("ndisasm")
      .arg("-b")
      .arg("64")
      .arg("-")
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .spawn()?;
    child.stdin.as_mut().unwrap().write_all(code)?;
  let output = child.wait_with_output()?;
  println!("{}", String::from_utf8_lossy(&output.stdout));

  Ok(())
}

unsafe fn jmp(addr: *const u8) {
  let fn_ptr: fn() = std::mem::transmute(addr);
  fn_ptr();
}

fn pause(reason: &str) -> Result<(), Box<dyn Error>> {
  println!("Press Enter to {}...", reason);
  {
      let mut s = String::new();
      std::io::stdin().read_line(&mut s)?;
  }
  Ok(())
}