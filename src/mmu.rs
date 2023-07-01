//! A very strict MMU with dirty page tracking
//! credit goes to @gamozolabs

use std::{ops::Range, path::Path};

use elf::{endian::AnyEndian, ElfBytes};

pub struct MMU {
    memory: Vec<u8>,
    permissions: Vec<Perm>,

    dirty_pages: Vec<usize>,
    dirty_bitmap: Vec<u64>,

    cur_alc: Virtaddr,
}

/// Block size used for resetting and tracking memory which has been modified
/// The larger this is, the fewer but more expensive memcpys() need to occur,
/// the small, the greater but less expensive memcpys() need to occur.
/// It seems the sweet spot is often 128-4096 bytes
pub const DIRTY_BLOCK_SIZE: usize = 64;

const STACK_SIZE: usize = 1024 * 1014;

impl MMU {
    pub fn new(size: usize) -> Self {
        MMU {
            memory: vec![0; size],
            permissions: vec![Perm(0); size],
            dirty_pages: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0u64; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alc: Virtaddr(0x10000),
        }
    }

    // copy self, treating the current state as undirtied
    pub fn fork(&self) -> Self {
        let size = self.memory.len();

        MMU {
            memory: self.memory.clone(),
            permissions: self.permissions.clone(),
            dirty_pages: Vec::with_capacity(size / DIRTY_BLOCK_SIZE + 1),
            dirty_bitmap: vec![0; size / DIRTY_BLOCK_SIZE / 64 + 1],
            cur_alc: self.cur_alc,
        }
    }

    /// Restores memory back to the original state (eg. restores all dirty
    /// blocks to the state of `other`)
    pub fn reset(&mut self, other: &MMU) {
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
    pub fn write_from(&mut self, addr: Virtaddr, buf: &[u8]) -> Result<(), ()> {
        self.write_from_perms(addr, buf, PERM_WRITE)
    }

    /// write a buffer to a virtual adress, checking if we have the given permissions
    pub fn write_from_perms(
        &mut self,
        addr: Virtaddr,
        buf: &[u8],
        exp_perm: Perm,
    ) -> Result<(), ()> {
        let mut has_raw = false;

        // check if we're not writing past the memory buffer
        // TODO: convert to checked add
        if buf.len() + addr.0 > self.memory.len() {
            return Err(());
        }

        // dbg!("checking permissions");
        // check if we have the permission, paying extra attention to if we have RAW
        // memory, to update the permissions later
        if !self.permissions[addr.0..addr.0 + buf.len()]
            .iter()
            .all(|&x| {
                has_raw |= (x & PERM_RAW).0 != 0;
                (x & exp_perm).0 != 0
            })
        {
            println!(
                "expected permission: {:#b}, got: {:#b}",
                exp_perm.0, self.permissions[addr.0].0
            );
            println!("perm check failed");
            return Err(());
        }
        // dbg!("after checking permissions");

        self.memory[addr.0..addr.0 + buf.len()].copy_from_slice(buf);
        // dbg!("after writing memory");

        // if the read after write flag is up, update the Permission of the memory
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
    pub fn read_to(&mut self, addr: Virtaddr, buf: &mut [u8]) -> Result<(), ()> {
        // check if we're reading past the memory buffer
        if buf.len() + addr.0 > self.memory.len() {
            return Err(());
        }

        // check if we have read permissions
        if !self.permissions[addr.0..addr.0 + buf.len()]
            .iter()
            .all(|&x| (x & PERM_READ).0 != 0)
        {
            return Err(());
        }

        // actually copy the memory
        buf.copy_from_slice(&self.memory[addr.0..addr.0 + buf.len()]);

        Ok(())
    }
    /// read from a virtual address to a buffer
    pub fn read_to_perms(
        &mut self,
        addr: Virtaddr,
        buf: &mut [u8],
        exp_perms: Perm,
    ) -> Result<(), ()> {
        // check if we're reading past the memory buffer
        if buf.len() + addr.0 > self.memory.len() {
            return Err(());
        }

        // check if we have read permissions
        if !self.permissions[addr.0..addr.0 + buf.len()]
            .iter()
            .all(|&x| x & exp_perms == exp_perms)
        {
            return Err(());
        }

        // actually copy the memory
        buf.copy_from_slice(&self.memory[addr.0..addr.0 + buf.len()]);

        Ok(())
    }

    /// write a primitive type to memory
    pub fn write_primitive<T: Copy>(&mut self, addr: Virtaddr, value: T) -> Result<(), ()> {
        // check if we are not writing past the memory buffer
        if addr.0 + std::mem::size_of::<T>() > self.memory.len() {
            return Err(());
        }

        // check if we have the permission
        if !self.permissions[addr.0..addr.0 + std::mem::size_of::<T>()]
            .iter()
            .all(|perm| (*perm & PERM_WRITE).0 != 0)
        {
            return Err(());
        }

        // acutally write the requested memory
        // the pointer casting here is needed,
        // since rust places an restriction of using `std::mem::sizeof::<T>()`
        // in the construction of arrays
        self.memory[addr.0..addr.0 + std::mem::size_of::<T>()].copy_from_slice(unsafe {
            core::slice::from_raw_parts(&value as *const T as *const u8, core::mem::size_of::<T>())
        });
        // self.memory[addr.0..addr.0 + std::mem::size_of::<T>()]
        //     .copy_from_slice(&value.to_ne_bytes());

        let block_start = addr.to_dirty_block();
        let block_end = Virtaddr(addr.0 + std::mem::size_of::<T>()).to_dirty_block();
        for block in block_start..=block_end {
            self.update_dirty(block)
        }

        Ok(())
    }

    /// Allocate a region of memory as RW in the address space
    pub fn allocate(&mut self, size: usize) -> Option<Virtaddr> {
        // 16-byte align the allocation
        let align_size = (size + 0xf) & !0xf;

        // Get the current allocation base
        let base = self.cur_alc;

        // Cannot allocate
        if base.0 >= self.memory.len() {
            return None;
        }

        // Update the allocation size
        self.cur_alc = Virtaddr(self.cur_alc.0.checked_add(align_size)?);

        // Could not satisfy allocation without going OOM
        if self.cur_alc.0 > self.memory.len() {
            return None;
        }

        // Mark the memory as un-initialized and writable
        if self
            .set_permissions(base, size, PERM_RAW | PERM_WRITE)
            .is_err()
        {
            return None;
        }

        Some(base)
    }
    /// this function reads primitives as [u8; N],
    /// this is to circumvent the restriction of using generic const expressions
    pub fn read_primitive<const N: usize>(&self, addr: Virtaddr) -> Result<[u8; N], ()> {
        // check if we are not writing past the memory buffer
        if addr.0 + N > self.memory.len() {
            return Err(());
        }

        // check if we have the permission
        if !self.permissions[addr.0..addr.0 + N]
            .iter()
            .all(|perm| (*perm & PERM_READ).0 != 0)
        {
            return Err(());
        }

        // copy the requested memory
        let mut buf = [0u8; N];
        buf.copy_from_slice(&self.memory[addr.0..addr.0 + N]);
        Ok(buf)
    }

    /// get acces to a mutable slice of memory
    pub fn peek(&self, addr: Virtaddr, size: usize, exp_perms: Perm) -> Result<&[u8], ()> {
        // check if we have the permission
        if !self.permissions[addr.0..addr.0 + size]
            .iter()
            .all(|perm| (*perm & exp_perms).0 != 0)
        {
            return Err(());
        }

        Ok(&self.memory[addr.0..addr.0 + size])
    }

    /// load an executable into the mmu to be executed later on
    /// this function pancis if it fails in any way
    /// gievs back `(entry_point, frame_pointer)`
    pub fn load<P: AsRef<Path>>(&mut self, filename: P) -> (Virtaddr, Virtaddr, Range<usize>) {
        let data = std::fs::read(filename).expect("failed to read the supplied elf file");

        let mut last_loaded_section = 0;

        let mut exec_range = Range { start: 0, end: 0 };

        // parse the elf
        let elf = ElfBytes::<AnyEndian>::minimal_parse(&data)
            .expect("failed to parse the supplied elf file");
        for hdr in elf
            .segments()
            .expect("failed parsing program headers of the elf")
        {
            match hdr.p_type {
                1 => {
                    // set the correct permissions
                    self.set_permissions(
                        Virtaddr(hdr.p_vaddr as usize),
                        hdr.p_memsz as usize,
                        PERM_WRITE,
                    )
                    .expect("failed to make program memory writable");

                    // load the section to the correct virtual adresses
                    self.write_from(
                        Virtaddr(hdr.p_vaddr as usize),
                        data.get(hdr.p_offset as usize..(hdr.p_offset + hdr.p_filesz) as usize)
                            .expect("failed to load file section"),
                    )
                    .expect("failed to write elf to memory");

                    // apply padding
                    if hdr.p_memsz > hdr.p_filesz {
                        let padding = vec![0u8; (hdr.p_memsz - hdr.p_filesz) as usize];
                        self.write_from(
                            Virtaddr(hdr.p_vaddr.checked_add(hdr.p_filesz).unwrap() as usize),
                            &padding,
                        )
                        .expect("somehow faild to apply padding to elf section");
                    }

                    last_loaded_section = std::cmp::max(hdr.p_vaddr, last_loaded_section);

                    // set the correct permissions
                    self.set_permissions(
                        Virtaddr(hdr.p_vaddr as usize),
                        hdr.p_memsz as usize,
                        Perm(hdr.p_flags as u8),
                    )
                    .expect("failed to set the permisssions for the loaded segement");
                    // #[cfg(debug_assertions)]
                    // if this section has exec permissions
                    if hdr.p_flags & (PERM_EXEC.0 as u32) != 0 {
                        // set this to our executable region
                        exec_range = hdr.p_paddr as usize..(hdr.p_paddr + hdr.p_memsz) as usize;
                    }
                }
                // if section type is INTERP, panic for now
                3 => todo!("make dynamic executables run"),
                // load the LOAD type sections
                x => println!("not loading section of type: {x}"),
            }
        }

        // add the stack
        self.set_permissions(
            // add 100 bytes of padding between the program and the stack
            Virtaddr(last_loaded_section as usize + 16),
            STACK_SIZE,
            PERM_WRITE | PERM_READ,
        )
        .expect("failed to allocate stack");

        // get the entry point and return it to the emulator
        (
            Virtaddr(elf.ehdr.e_entry as usize),
            Virtaddr(last_loaded_section as usize + STACK_SIZE),
            exec_range,
        )
    }

    /// set the permissions specified in `perms` to a memory segment of size `size`
    /// at the the virtual address located at `addr`
    /// this function will fail if either we have an overflow by adding `size` to `addr` or
    /// `size` + `addr` is out of our memory space
    fn set_permissions(&mut self, addr: Virtaddr, size: usize, perms: Perm) -> Result<(), ()> {
        // nothing to do, just continue
        if size == 0 {
            return Ok(());
        }

        let Some(end_addr) = addr.0.checked_add(size) else { return Err(())};
        let Some(region) = self.permissions.get_mut(addr.0..end_addr) else {return Err(());};
        region.iter_mut().for_each(|x| *x = perms);

        // compute the dirty bit blocks
        let block_start = addr.to_dirty_block();
        let block_end = Virtaddr(addr.0 + size).to_dirty_block();

        // update the dirty blocks
        for block in block_start..=block_end {
            self.update_dirty(block)
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Virtaddr(pub usize);

impl Virtaddr {
    #[inline]
    fn to_dirty_block(&self) -> usize {
        self.0 / DIRTY_BLOCK_SIZE
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Perm(u8);

/// permission to read a byte in memory
pub const PERM_READ: Perm = Perm(1 << 2);
/// permission to write a byte in memory
pub const PERM_WRITE: Perm = Perm(1 << 1);
/// permission to read a byte in memory after writing to it
/// this can be useful for detecting unintialized reads
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
