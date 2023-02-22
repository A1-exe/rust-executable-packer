// in `elk/src/main.rs`
use std::{env, error::Error, fs, mem::transmute, ptr::copy_nonoverlapping};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
  let input_path = env::args().nth(1).expect("usage: elk FILE");
  let input = fs::read(&input_path)?;
  
  println!("Analyzing {:?}...", input_path);
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
  
  // println!("Disassembling {:?}...", input_path);
  // let code_ph = file
  // .program_headers
  // .iter()
  // .find(|ph| ph.mem_range().contains(&file.entry_point))
  // .expect("segment with entry point not found");
  
  // ndisasm(&code_ph.data[..], file.entry_point)?;
  
  let rela_entries = file.read_rela_entries().unwrap_or_else(|e| {
    println!("Could not read relocations: {:?}", e);
    Default::default()
  });
  let base = 0x400000_usize;
  
  println!("Loading with base address @ 0x{:x}", base);
  let non_empty_load_segments = file
    .program_headers
    .iter()
    .filter(|ph| ph.r#type == delf::SegmentType::Load)
    // ignore zero-length segments
    .filter(|ph| ph.mem_range().end > ph.mem_range().start);
  
  // we'll need to hold onto our "mmap::MemoryMap", because dropping them
  // unmaps the memory
  let mut mappings = Vec::new();
  
  // we're only interested in "Load" segments
  for ph in non_empty_load_segments {
    let mem_range = ph.mem_range();
    println!("Mapping {:?} - {:?}", mem_range, ph.flags);
    // note: mmap-ing would fail if the segments weren't aligned on page boundaries,
    // but luckily, that is the case in the file already. That is not a coincidence.
    let len: usize = (mem_range.end - mem_range.start).into();
    
    // add base offset to the program header's virtual address
    let start: usize = mem_range.start.0 as usize + base;
    let aligned_start: usize = align_lo(start);
    let padding = start - aligned_start;
    let len = len + padding;
    
    // `as` is the "cast" operator, and `_` is a placeholder to force rustc
    // to infer the tpe based on other hints
    let addr: *mut u8 = aligned_start as _;
    if padding > 0 {
      println!("(With 0x{:x} bytes of padding at the start)", padding);
    }
    
    // at first, we want the memory area to be writable, so we can copy to it
    let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)])?;
    
    // println!("Copying segment data...");
    unsafe {
      copy_nonoverlapping(ph.data.as_ptr(), addr.add(padding), len);
  }
    
    // println!("Applying relocations (if any)...");
    let mut num_relocs = 0;
    for reloc in &rela_entries {
      if mem_range.contains(&reloc.offset) {
        num_relocs += 1;
        unsafe {
          let real_segment_start = addr.add(padding);
          let offset_into_segment = reloc.offset - mem_range.start;
          let reloc_addr = real_segment_start.add(offset_into_segment.into());
          
          match reloc.r#type {
            delf::RelType::Relative => {
              // this assumes `reloc_addr` is 8-byte aligned. if this isn't
              // the case, we would crash, and so would the target executable.
              let reloc_addr: *mut u64 = transmute(reloc_addr);
              let reloc_value = reloc.addend + delf::Addr(base as u64);
              *reloc_addr = reloc_value.0;
            }
            r#type => {
              panic!("Unsupported relocation type {:?}", r#type);
            }
          }
        }
      }
    }
    if num_relocs > 0 {
      println!("(Applied {} relocations)", num_relocs);
    }
    
    // println!("Adjusting memory protection...");
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
  
  println!("Jumping to entry point @ {:?}...", file.entry_point);
  pause("jmp")?;
  unsafe {
    jmp(transmute(file.entry_point.0 as usize + base));
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

/**
* Truncates a usize value to the left-adjacent (low) 4KiB boundary.
*/
fn align_lo(x: usize) -> usize {
  x & !0xFFF
}