//! A very strict MMU with dirty page tracking
//! credit goes to @gamozolabs

use core::ops::Range;
use std::{fmt::Debug, path::Path};

use elf::{endian::LittleEndian, ElfBytes};

use crate::{primitive::Primitive, symbol_table::SymbolTable};

pub struct MMU {
    memory: Vec<u8>,
    permissions: Vec<Perm>,

    dirty_pages: Vec<usize>,
    dirty_bitmap: Vec<u64>,

    pub cur_alc: Virtaddr,

    symbol_table: SymbolTable,
}

/// Block size used for resetting and tracking memory which has been modified
/// The larger this is, the fewer but more expensive memcpys() need to occur,
/// the small, the greater but less expensive memcpys() need to occur.
/// It seems the sweet spot is often 128-4096 bytes
pub const DIRTY_BLOCK_SIZE: usize = 64;

const STACK_SIZE: usize = 4096 * 0x10;

type Result<T> = std::result::Result<T, AccessError>;

impl MMU {
    pub fn new(size: usize) -> Self {
        Self {
            memory: vec![0; size],
            permissions: vec![Perm(0); size],
            dirty_pages: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alc: Virtaddr(0x10000),
            symbol_table: SymbolTable::new(),
        }
    }

    // copy self, treating the current state as undirtied
    pub fn fork(&self) -> Self {
        let size = self.memory.len();

        Self {
            memory: self.memory.clone(),
            permissions: self.permissions.clone(),
            dirty_pages: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alc: self.cur_alc,
            symbol_table: SymbolTable::new(),
        }
    }

    /// Restores memory back to the original state (eg. restores all dirty
    /// blocks to the state of `other`)
    pub fn reset(&mut self, other: &Self) {
        for &block in &self.dirty_pages {
            let start = block * DIRTY_BLOCK_SIZE;
            let end = (block + 1) * DIRTY_BLOCK_SIZE;

            self.dirty_bitmap[block / 64] = 0;

            self.memory[start..end].copy_from_slice(&other.memory[start..end]);

            self.permissions[start..end].copy_from_slice(&other.permissions[start..end]);
        }

        self.dirty_pages.clear();

        debug_assert_eq!(self.memory, other.memory);
        debug_assert_eq!(self.permissions, other.permissions);
    }

    /// toggle dirty blocks
    #[inline]
    fn update_dirty(&mut self, block: usize) {
        // let block = addr.0 / DIRTY_BLOCK_SIZE;

        // determine bimap position of block
        let idx = block / 64;
        let bit = block % 64;

        // check if the block is already tracked
        if self.dirty_bitmap[idx] & (1 << bit) == 0 {
            // block is not tracked, push it
            self.dirty_pages.push(block);

            // update the dirty bitmap
            self.dirty_bitmap[idx] |= 1 << bit;
        }
    }

    /// write a buffer to a virtual adress
    pub fn write_from(&mut self, addr: Virtaddr, buf: &[u8]) -> Result<()> {
        self.write_from_perms(addr, buf, PERM_WRITE)
    }

    /// write a buffer to a virtual adress, checking if we have the given permissions
    pub fn write_from_perms(&mut self, addr: Virtaddr, buf: &[u8], exp_perm: Perm) -> Result<()> {
        #[cfg(feature = "raw_tracking")]
        let mut has_raw = false;

        // check if we're not writing past the memory buffer
        // TODO: convert to checked add
        if buf.len() + addr.0 > self.memory.len() {
            return Err(AccessError::AddrOOB);
        }

        // dbg!("checking permissions");
        // check if we have the permission, paying extra attention to if we have RAW
        // memory, to update the permissions later
        #[cfg(feature = "raw_tracking")]
        if !self.permissions[addr.0..addr.0 + buf.len()]
            .iter()
            .all(|&x| {
                has_raw |= (x & PERM_RAW).0 != 0;
                (x & exp_perm).0 != 0
            })
        {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        }
        #[cfg(not(feature = "raw_tracking"))]
        if !self.permissions[addr.0..addr.0 + buf.len()]
            .iter()
            .all(|&x| (x & exp_perm).0 != 0)
        {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        }
        // dbg!("after checking permissions");

        self.memory[addr.0..addr.0 + buf.len()].copy_from_slice(buf);
        // dbg!("after writing memory");

        // if the read after write flag is up, update the Permission of the memory
        #[cfg(feature = "raw_tracking")]
        if has_raw {
            self.permissions.iter_mut().for_each(|x| {
                if (*x & PERM_RAW).0 != 0 {
                    *x = (*x | PERM_READ) & !PERM_RAW
                }
            })
        }

        let block_start = addr.to_dirty_block();
        let block_end = Virtaddr(addr.0 + buf.len()).to_dirty_block();
        for block in block_start..=block_end {
            self.update_dirty(block)
        }

        Ok(())
    }

    /// read from a virtual address to a buffer
    pub fn read_to(&mut self, addr: Virtaddr, buf: &mut [u8]) -> Result<()> {
        // check if we're reading past the memory buffer
        if buf.len() + addr.0 > self.memory.len() {
            return Err(AccessError::AddrOOB);
        }

        // check if we have read permissions
        if !self.permissions[addr.0..addr.0 + buf.len()]
            .iter()
            .all(|&x| (x & PERM_READ).0 != 0)
        {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        }

        // actually copy the memory
        buf.copy_from_slice(&self.memory[addr.0..addr.0 + buf.len()]);

        Ok(())
    }
    /// read from a virtual address to a buffer
    pub fn read_to_perms(&mut self, addr: Virtaddr, buf: &mut [u8], exp_perms: Perm) -> Result<()> {
        // check if we're reading past the memory buffer
        if buf.len() + addr.0 > self.memory.len() {
            return Err(AccessError::AddrOOB);
        }

        // check if we have read permissions
        if !self.permissions[addr.0..addr.0 + buf.len()]
            .iter()
            .all(|&x| x & exp_perms == exp_perms)
        {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        }

        // actually copy the memory
        buf.copy_from_slice(&self.memory[addr.0..addr.0 + buf.len()]);

        Ok(())
    }

    /// write a primitive type to memory
    pub fn write_primitive<T: Primitive<BYTES>, const BYTES: usize>(
        &mut self,
        addr: Virtaddr,
        value: T,
    ) -> Result<()> {
        if addr.0 == 0x00474688 {
            panic!()
        }

        // check if we are not writing past the memory buffer
        if addr.0 + std::mem::size_of::<T>() > self.memory.len() {
            return Err(AccessError::AddrOOB);
        }

        // check if we have the permission
        if !self.permissions[addr.0..addr.0 + std::mem::size_of::<T>()]
            .iter()
            .all(|perm| (*perm & PERM_WRITE).0 != 0)
        {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        }

        // acutally write the requested memory
        // the pointer casting here is needed,
        // since rust places an restriction of using `std::mem::sizeof::<T>()`
        // in the construction of arrays
        self.memory[addr.0..addr.0 + std::mem::size_of::<T>()]
            .copy_from_slice(&value.to_ne_bytes());
        // self.memory[addr.0..addr.0 + std::mem::size_of::<T>()]
        //     .copy_from_slice(&value.to_ne_bytes());

        let block_start = addr.to_dirty_block();
        let block_end = Virtaddr(addr.0 + std::mem::size_of::<T>()).to_dirty_block();
        for block in block_start..=block_end {
            self.update_dirty(block)
        }

        Ok(())
    }

    /// write a primitive type to memory
    /* fn write_primitive_no_check<T: Primitive<BYTES>, const BYTES: usize>(
        &mut self,
        addr: Virtaddr,
        value: T,
    ) -> Result<()> {
        // check if we are not writing past the memory buffer
        if addr.0 + std::mem::size_of::<T>() > self.memory.len() {
            return Err(AccessError::AddrOOB);
        }

        // acutally write the requested memory
        // the pointer casting here is needed,
        // since rust places an restriction of using `std::mem::sizeof::<T>()`
        // in the construction of arrays
        self.memory[addr.0..addr.0 + std::mem::size_of::<T>()]
            .copy_from_slice(&value.to_ne_bytes());
        // self.memory[addr.0..addr.0 + std::mem::size_of::<T>()]
        //     .copy_from_slice(&value.to_ne_bytes());

        let block_start = addr.to_dirty_block();
        let block_end = Virtaddr(addr.0 + std::mem::size_of::<T>()).to_dirty_block();
        for block in block_start..=block_end {
            self.update_dirty(block)
        }

        Ok(())
    }*/

    /// Allocate a region of memory as RW in the address space
    /// returns (base, cur_alc)
    pub fn allocate(&mut self, size: usize) -> Option<(Virtaddr, Virtaddr)> {
        // 16-byte align the allocation
        // this is required for SSE memcpy
        let align_size = (size + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alc;

        // Update the allocation address
        self.cur_alc = Virtaddr(self.cur_alc.0.checked_add(align_size)?);

        // Could not satisfy allocation without going OOM
        if self.cur_alc.0 > self.memory.len() {
            return None;
        }

        // Mark the memory as un-initialized and writable
        #[cfg(feature = "raw_tracking")]
        if self
            .set_permissions(base, align_size, PERM_RAW | PERM_WRITE)
            .is_err()
        {
            return None;
        }
        #[cfg(not(feature = "raw_tracking"))]
        if self
            .set_permissions(base, align_size, PERM_WRITE | PERM_READ)
            .is_err()
        {
            return None;
        }

        Some((base, self.cur_alc))
    }

    /// Allocate a region the size of buf in memery as RW, writing buf to it
    /// returns (base, cur_alc)
    pub fn allocate_write(&mut self, buf: &[u8]) -> Option<(Virtaddr, Virtaddr)> {
        // 16-byte align the allocation
        // this is required for SSE memcpy
        let align_size = (buf.len() + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alc;

        // Update the allocation address
        self.cur_alc = Virtaddr(self.cur_alc.0.checked_add(align_size)?);

        // Could not satisfy allocation without going OOM
        if self.cur_alc.0 > self.memory.len() {
            return None;
        }

        if self
            .set_permissions(base, align_size, PERM_WRITE | PERM_READ)
            .is_err()
        {
            return None;
        }

        self.write_from(base, buf).unwrap();

        Some((base, self.cur_alc))
    }

    pub fn read_cstr(&self, start_addr: Virtaddr, max_size: usize) -> &[u8] {
        std::ffi::CStr::from_bytes_until_nul(&self.memory[start_addr.0..start_addr.0 + max_size])
            .unwrap()
            .to_bytes()
    }
    /// this function reads primitives as [u8; N],
    /// this is to circumvent the restriction of using generic const expressions
    pub fn read_primitive<const N: usize, T: Primitive<N>>(&self, addr: Virtaddr) -> Result<T> {
        // check if we are not writing past the memory buffer
        let Some(last_addr) = addr.0.checked_add(N) else {
            return Err(AccessError::AddrOverflow);
        };
        if last_addr > self.memory.len() {
            return Err(AccessError::AddrOOB);
        }

        // check if we have the permission
        if !self.permissions[addr.0..last_addr]
            .iter()
            .all(|perm| (*perm & PERM_READ).0 != 0)
        {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        }

        // copy the requested memory
        let mut buf = [0u8; N];
        buf.copy_from_slice(&self.memory[addr.0..last_addr]);
        Ok(T::from_ne_bytes(buf))
    }

    /// get acces to a mutable slice of memory
    pub fn peek(&self, addr: Virtaddr, size: usize, exp_perms: Perm) -> Result<&[u8]> {
        // check if we have the permission
        if exp_perms != Perm(0)
            && !self.permissions[addr.0..addr.0 + size]
                .iter()
                .all(|perm| (*perm & exp_perms).0 != 0)
        {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        }

        Ok(&self.memory[addr.0..addr.0 + size])
    }

    pub fn get_sym(&self, addr: usize) -> &str {
        self.symbol_table
            .get(&addr)
            .map_or("<can't resolve>", String::as_str)
    }

    /// load an executable into the mmu to be executed later on
    /// this function pancis if it fails in any way
    /// gievs back `(entry_point, frame_pointer)`
    pub fn load<P: AsRef<Path>>(
        &mut self,
        filename: P,
    ) -> (elf::file::FileHeader<LittleEndian>, Virtaddr, Range<usize>) {
        let data = std::fs::read(filename).expect("failed to read the supplied elf file");

        let mut last_loaded_section = 0;

        let mut exec_range = Range { start: 0, end: 0 };

        // parse the elf
        let elf = ElfBytes::<LittleEndian>::minimal_parse(&data)
            .expect("failed to parse the supplied elf file");

        // get the symbol table
        // let mut sym_table = Vec::new();
        let (sym_tab, string_tab) = elf.symbol_table().unwrap().unwrap();
        for symbol in sym_tab.clone() {
            // sym_table .push(symbol);
            let name = string_tab.get(symbol.st_name as usize).unwrap();
            let addr = symbol.st_value;

            self.symbol_table.insert(addr as usize, name.to_string());
        }

        for hdr in elf
            .segments()
            .expect("failed parsing program headers of the elf")
        {
            match hdr.p_type {
                // TLS or LOAD
                1 | 7 | 4 => {
                    if hdr.p_memsz == 0 {
                        continue;
                    }
                    // set the correct permissions
                    self.set_permissions(
                        Virtaddr(hdr.p_vaddr as usize),
                        hdr.p_memsz as usize,
                        PERM_WRITE,
                    )
                    .expect("failed to make program memory writable");

                    println!(
                        "loading section to: {:#x}...{:#x}",
                        hdr.p_vaddr,
                        hdr.p_vaddr + hdr.p_memsz
                    );

                    /* if let Ok(relocs) = elf.section_data_as_relas(&hdr) {

                    } */

                    // load the section to the correct virtual adresses
                    self.write_from(
                        Virtaddr(hdr.p_vaddr as usize),
                        elf.segment_data(&hdr).expect("failed to load file section"),
                    )
                    .expect("failed to write elf to memory");
                    assert!(elf.segment_data(&hdr).unwrap().len() == hdr.p_filesz as usize);

                    // apply padding
                    /* if hdr.p_memsz > hdr.p_filesz {
                        let padding = vec![0u8; (hdr.p_memsz - hdr.p_filesz) as usize];
                        self.write_from(
                            Virtaddr(hdr.p_vaddr.checked_add(hdr.p_filesz).unwrap() as usize),
                            &padding,
                        )
                        .expect("somehow faild to apply padding to elf section");

                    }*/

                    last_loaded_section =
                        std::cmp::max(hdr.p_vaddr + hdr.p_filesz, last_loaded_section);

                    // set the correct permissions
                    self.set_permissions(
                        Virtaddr(hdr.p_vaddr as usize),
                        hdr.p_memsz as usize + 14,
                        Perm(hdr.p_flags as u8),
                    )
                    .expect("failed to set the permisssions for the loaded segement");
                    // #[cfg(debug_assertions)]
                    // if this section has exec permissions
                    if hdr.p_flags & (PERM_EXEC.0 as u32) != 0 {
                        // set this to our executable region
                        exec_range =
                            hdr.p_vaddr as usize..(hdr.p_vaddr + hdr.p_memsz + 0xff) as usize;
                    }
                }
                // if section type is INTERP, panic for now
                3 => todo!("make dynamic executables run"),
                // GNU relro
                1685382482 => {
                    println!(
                        "GNU relro at: {:#x}...{:#x}",
                        hdr.p_vaddr,
                        hdr.p_vaddr + hdr.p_filesz
                    );
                    self.set_permissions(
                        Virtaddr(hdr.p_vaddr as usize),
                        hdr.p_memsz as usize,
                        PERM_READ | PERM_WRITE,
                    )
                    .unwrap();

                    // load the section to the correct virtual adresses
                    self.write_from(
                        Virtaddr(hdr.p_vaddr as usize),
                        elf.segment_data(&hdr).expect("failed to load file section"),
                    )
                    .expect("failed to write elf to memory");

                    last_loaded_section =
                        std::cmp::max(hdr.p_vaddr + hdr.p_filesz, last_loaded_section);
                }
                // load the LOAD type sections
                x => println!("not loading section of type: {x}"),
            }
        }

        for shdr in elf.section_headers().unwrap() {
            if let Ok(rels) = elf.section_data_as_relas(&shdr) {
                for rel in rels {
                    // let sym = sym_tab.get(rel.r_sym as usize).unwrap();
                    println!("{rel:#x?}");
                    // let's pretend we're libc ;)
                    /*match rel.r_type {
                        0x25 => {
                            self.write_primitive_no_check(
                                Virtaddr(rel.r_offset as usize),
                                rel.r_addend,
                            )
                            .unwrap();
                        }
                        x => println!("unsupported relocation type {x:#x}"),
                    }*/
                }
            }
            /*if let Ok(rels) = elf.section_data_as_rels(&shdr) {
                for rel in rels {
                    let sym = sym_tab.get(rel.r_sym as usize).unwrap();
                    println!("{rel:#x?}");
                }
            }*/
        }

        let stack_end = Virtaddr(last_loaded_section.next_multiple_of(0x1000) as usize);

        // add the stack
        self.set_permissions(stack_end, STACK_SIZE, PERM_WRITE | PERM_READ)
            .expect("failed to allocate stack");

        self.cur_alc = Virtaddr(stack_end.0 + 0x10 + STACK_SIZE);

        // get the entry point and return it to the emulator
        (elf.ehdr, Virtaddr(stack_end.0 + STACK_SIZE), exec_range)
    }

    /// set the permissions specified in `perms` to a memory segment of size `size`
    /// at the the virtual address located at `addr`
    /// this function will fail if either we have an overflow by adding `size` to `addr` or
    /// `size` + `addr` is out of our memory space
    pub fn set_permissions(&mut self, addr: Virtaddr, size: usize, perms: Perm) -> Result<()> {
        // nothing to do, just continue
        if size == 0 {
            return Ok(());
        }

        let Some(end_addr) = addr.0.checked_add(size) else {
            return Err(AccessError::AddrOverflow);
        };
        let Some(region) = self.permissions.get_mut(addr.0..end_addr) else {
            return Err(AccessError::PermErr(addr, self.permissions[addr.0]));
        };
        region.iter_mut().for_each(|x| *x = perms);

        // compute the dirty bit blocks
        let block_start = addr.to_dirty_block();
        let block_end = Virtaddr(addr.0 + size).to_dirty_block();

        // update the dirty blocks
        for block in block_start..=block_end {
            self.update_dirty(block);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Virtaddr(pub usize);

impl Virtaddr {
    #[inline]
    const fn to_dirty_block(self) -> usize {
        self.0 / DIRTY_BLOCK_SIZE
    }
}

/// error type for memory acces operations
#[derive(Debug, Clone, Copy)]
pub enum AccessError {
    /// We had an overflow when trying to get
    /// the end of the region to access
    AddrOverflow,
    /// We tried to acces past the memory buffer
    AddrOOB,
    /// We tried to acces memory without the
    /// needed permissions
    PermErr(Virtaddr, Perm),
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Perm(pub u8);

impl Debug for Perm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut buf = String::new();
        if (self.0 & PERM_READ.0) > 0 {
            buf.push('R');
        } else {
            buf.push('-');
        }
        if (self.0 & PERM_WRITE.0) > 0 {
            buf.push('W');
        } else {
            buf.push('-');
        }
        if (self.0 & PERM_EXEC.0) > 0 {
            buf.push('X');
        } else {
            buf.push('-');
        }
        f.debug_tuple("Perm")
            .field_with(|f| f.write_str(&buf))
            .finish()
    }
}

/// permission to read a byte in memory
pub const PERM_READ: Perm = Perm(1 << 2);
/// permission to write a byte in memory
pub const PERM_WRITE: Perm = Perm(1 << 1);
/// permission to read a byte in memory after writing to it
/// this can be useful for detecting unintialized reads
#[cfg(feature = "raw_tracking")]
pub const PERM_RAW: Perm = Perm(1 << 3);
/// permission to execute a byte in memory
pub const PERM_EXEC: Perm = Perm(1 << 0);

impl std::ops::BitOr for Perm {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
impl std::ops::BitAnd for Perm {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}
impl std::ops::Not for Perm {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}
