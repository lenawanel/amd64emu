use core::fmt::Debug;
use std::{
    path::Path,
    simd::{
        cmp::{SimdOrd, SimdPartialEq},
        i8x16, simd_swizzle, u16x8, u32x4, u64x2, u8x16, u8x8, Mask, Simd,
    },
};

use elf::{endian::LittleEndian, file::FileHeader};
// this is impossible to because of https://github.com/bitdefender/bddisasm/issues/82 ;(
// use bddisasm::{operand::Operands, DecodedInstruction, OpInfo, Operand};
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};

#[cfg(debug_assertions)]
use crate::mmu::PERM_EXEC;
use crate::{
    mmu::{AccessError, Perm, Virtaddr, MMU, PERM_READ},
    primitive::Primitive,
};
#[cfg(debug_assertions)]
use std::{io::Write, ops::Range};

pub struct Emu {
    pub memory: MMU,
    registers: [u64; 17],
    simd_registers: [u128; 17],
    segment_registers: [u64; 2],
    #[cfg(debug_assertions)]
    pub stack_depth: usize,
    #[cfg(debug_assertions)]
    exec_range: Range<usize>,
    rng: usize,
    rflags: u64,
}

// TODO: avoid this
#[thread_local]
static mut IP: u64 = 0;

type Result<T> = std::result::Result<T, ExecErr>;

impl Emu {
    #[inline(always)]
    fn rng<const BYTES: usize, T: Primitive<BYTES>>(&mut self) -> T
    where
        <T as TryFrom<usize>>::Error: Debug,
    {
        self.rng = self.rng.wrapping_add(1);
        self.rng.try_into().unwrap()
    }

    // for reference https://github.com/jart/blink/blob/master/blink/argv.c
    fn prepare_auxv(&mut self, progname: Virtaddr, ehdr: FileHeader<LittleEndian>) {
        fn push_auxv(emu: &mut Emu, k: u64, v: u64) {
            emu.push(v);
            emu.push(k);
        }

        let rand = self
            .memory
            .allocate_write(&[
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                0xbe, 0xef,
            ])
            .unwrap()
            .0;

        push_auxv(self, 0, 0);
        push_auxv(self, 11, 1000);
        push_auxv(self, 12, 1000);
        push_auxv(self, 13, 1000);
        push_auxv(self, 14, 1000);
        push_auxv(self, 23, 0);
        push_auxv(self, 6, 4096);
        push_auxv(self, 17, 100);
        push_auxv(self, 25, rand.0 as u64);
        push_auxv(self, 31, progname.0 as u64);

        // elf header info
        // TODO: very dubious
        push_auxv(self, 3, ehdr.e_phoff + 0x400000);
        push_auxv(self, 4, ehdr.e_phentsize as u64);
        push_auxv(self, 5, ehdr.e_phnum as u64);
        push_auxv(self, 9, ehdr.e_entry);
        push_auxv(self, 17, 100);

        push_auxv(self, 7, 0x400000);
    }

    fn push<const SIZE: usize>(&mut self, n: impl Primitive<SIZE>) {
        let sp = self.get_reg::<u64, 8>(Register::RSP) as usize - SIZE;
        self.memory
            .write_primitive(Virtaddr(sp), n)
            .expect("Push failed");
        self.set_reg(sp, Register::RSP);
    }

    pub fn load<P: AsRef<Path>>(&mut self, file: P) {
        let (ehdr, frame, exec_range) = self.memory.load(file);
        self.set_reg(ehdr.e_entry, Register::RIP);
        self.set_reg(frame.0, Register::RSP);
        // self.set_reg(frame.0 as u64 - 8, Register::RBP);

        #[cfg(debug_assertions)]
        {
            self.exec_range = exec_range;
        }

        // Set up the program name
        let progname = self
            .memory
            .allocate_write(b"/bin/test\0")
            .expect("Failed to write program name")
            .0;
        self.prepare_auxv(progname, ehdr);

        // Set up the program name
        let argv = self
            .memory
            .allocate_write(b"/bin/test\0")
            .expect("Failed to write program name")
            .0;

        self.set_reg(argv.0, Register::RDX);

        // Set up the initial program stack state
        // self.push(auxv.0 as u64); // Auxp
        // self.push(0u64); // Envp end
        self.push(0u64); // Envp end
        self.push(0u64); // Argv end
        self.push(argv.0); // Argv [0]
        self.push(1u64); // Argc

        println!("sp at: {:x}", self.get_reg::<usize, 8>(Register::RSP));
    }

    pub fn new(size: usize) -> Self {
        Self {
            memory: MMU::new(size),
            registers: [0; 17],
            simd_registers: [0; 17],
            #[cfg(debug_assertions)]
            stack_depth: 0,
            #[cfg(debug_assertions)]
            exec_range: Range { start: 0, end: 0 },
            segment_registers: [0; 2],
            rng: 0,
            rflags: 0b10,
        }
    }

    #[inline]
    pub fn set_reg<T: Primitive<BYTES>, const BYTES: usize>(&mut self, val: T, register: Register)
    where
        <T as TryInto<u16>>::Error: Debug,
        <T as TryInto<u32>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        #[cfg(debug_assertions)]
        if register == Register::RSP && self.registers[Register::RSP as usize] != 0 {
            self.stack_depth = (self.stack_depth as isize
                + self.registers[Register::RSP as usize] as isize
                - (val.to_u64() as isize)) as usize;
        }
        if (register as u8) < self.registers.len() as u8 {
            self.registers[register as usize] = val.to_u64();
        } else if (register as u8) < (Register::AH as u8) {
            // we're a 128 bit register
            self.simd_registers[register as usize - self.registers.len()] = val.try_into().unwrap();
        } else {
            // we're the high part of an register
            // so first mask off the unused bits
            self.registers
                [register as usize - self.registers.len() - self.simd_registers.len() + 2] &=
                !0xff_00;
            // then set it to it's new value
            self.registers
                [register as usize - self.registers.len() - self.simd_registers.len() + 2] |=
                TryInto::<u16>::try_into(val).unwrap().overflowing_shl(8).0 as u64;
        }
    }

    // TODO: make this less disgusting
    #[inline]
    pub fn get_reg<T: Primitive<BYTES>, const BYTES: usize>(&self, register: Register) -> T
    where
        <T as TryFrom<u16>>::Error: Debug,
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
    {
        if (register as u8) < self.registers.len() as u8 {
            let mut bytes: [u8; BYTES] = [0; BYTES];
            bytes.copy_from_slice(&self.registers[register as usize].to_ne_bytes()[..BYTES]);
            T::from_ne_bytes(bytes)
        } else if (register as u8) < (Register::AH as u8) {
            self.simd_registers[register as usize - self.registers.len()]
                .try_into()
                .unwrap()
        } else {
            // we're the high part of a 16 bit lower register
            T::try_from(
                ((self.registers
                    [register as usize - self.registers.len() - self.simd_registers.len() + 2]
                    as u16)
                    & 0xff_00)
                    >> 8,
            )
            .unwrap()
        }
    }

    #[inline]
    fn set_flag(&mut self, flag: Flag) {
        self.rflags |= flag as u64;
    }
    #[inline]
    fn unset_flag(&mut self, flag: Flag) {
        self.rflags &= !(flag as u64);
    }
    #[inline]
    fn get_flag(&self, flag: Flag) -> bool {
        (self.rflags & flag as u64) != 0
    }

    #[inline]
    pub fn get_val<T: Primitive<BYTES>, const BYTES: usize>(
        &self,
        instruction: Instruction,
        index: u32,
    ) -> Result<T>
    where
        <T as TryFrom<u8>>::Error: Debug,
        <T as TryFrom<u16>>::Error: Debug,
        <T as TryFrom<u32>>::Error: Debug,
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
    {
        let operand = instruction.op_kind(index);
        match operand {
            OpKind::Register => {
                let reg: Register = reg_from_iced_reg(instruction.op_register(index)).unwrap();
                Ok(self.get_reg(reg))
            }
            OpKind::NearBranch64 => Ok(instruction.near_branch64().try_into().unwrap()),
            OpKind::Immediate8 => Ok(T::try_from(instruction.immediate8()).unwrap()),
            OpKind::Immediate16 => Ok(T::try_from(instruction.immediate16()).unwrap()),
            OpKind::Immediate32 => Ok(T::try_from(instruction.immediate32()).unwrap()),
            OpKind::Immediate64 => Ok(T::try_from(instruction.immediate64()).unwrap()),
            OpKind::Immediate8to16 => Ok(T::try_from(instruction.immediate8to16() as u16)
                .map_err(|_| ())
                .unwrap()),
            OpKind::Immediate8to32 => Ok(T::try_from(instruction.immediate8to32() as u32)
                .map_err(|_| ())
                .unwrap()),
            OpKind::Immediate8to64 => Ok(T::try_from(instruction.immediate8to64() as u64).unwrap()),
            OpKind::Immediate32to64 => {
                Ok(T::try_from(instruction.immediate32to64() as u64).unwrap())
            }
            OpKind::Memory => {
                let address: usize = self.calc_addr(instruction);
                Ok(self.memory.read_primitive(Virtaddr(address))?)
            }
            x => todo!("{x:?}"),
        }
    }

    #[cfg(debug_assertions)]
    /// pretty print the stack, looking `length` `T`'s down from RSP
    pub fn print_stack<T: Primitive<BYTES>, const BYTES: usize>(&self, length: usize)
    where
        usize: TryFrom<T>,
        <usize as TryFrom<T>>::Error: Debug,
        <T as TryFrom<usize>>::Error: Debug,
    {
        let stack_addr: usize = self.get_reg(Register::RSP);
        println!("\x1b[1mStack:\x1b[0m");
        for val in (stack_addr..stack_addr + (length)).step_by(BYTES) {
            let mut val = T::try_from(val).unwrap();
            print!("\x1b[;91m    {val:#x?}");
            let mut depth = 0;
            'recursive_memory_lookup: while let Ok(new_val) = self
                .memory
                .read_primitive(Virtaddr(usize::try_from(val).unwrap()))
            {
                val = new_val;
                let val_addr = usize::try_from(val).unwrap();
                print!("\x1b[0m -> ");

                // if we know this is part of a executable region
                if self.exec_range.contains(&val_addr) {
                    // peak 16 bytes into memory
                    if let Ok(inst_buf) = self.memory.peek(Virtaddr(val_addr), 16, PERM_EXEC) {
                        let decoder = Decoder::new(64, inst_buf, 0);
                        let mut formatter = NasmFormatter::new();
                        let mut instr_str = String::new();
                        for inst in decoder.into_iter() {
                            if inst.is_invalid() {
                                // skip invalid instrucions
                                continue;
                            }
                            formatter.format(&inst, &mut instr_str);
                            // instr_str.push(' ');
                            instr_str.push(';');
                            instr_str.push(' ');
                        }
                        print!("\x1b[;96m{val:#x?}\x1b[0m -> ");
                        print!("\x1b[38;2;255;100;0m{}\x1b[0m", instr_str);
                        break 'recursive_memory_lookup;
                    }
                }
                depth += 1;
                if depth > 5 {
                    break 'recursive_memory_lookup;
                }
                print!("\x1b[;96m{val:#x?}\x1b[0m");
            }
            println!("\x1b[0m");
        }
    }

    pub fn get_seg(&self, reg: SegReg) -> u64 {
        self.segment_registers[reg as usize]
    }
    pub fn set_seg(&mut self, reg: SegReg, val: u64) {
        self.segment_registers[reg as usize] = val;
    }

    pub fn run_emu(&mut self) -> Result<()> {
        #[cfg(debug_assertions)]
        let mut call_depth = 0;
        'next_instr: loop {
            // std::thread::sleep(Duration::from_nanos(50));
            // we have to look ahead 16 bytes into memory since that's the maximum size of x86 instructions

            #[cfg(debug_assertions)]
            if false {
                // cls
                print!("\x1b[2J\x1b[1;1H");
                self.trace();
                self.print_stack::<u64, 8>((self.stack_depth - 3 * 8).min(30 * 16));
                print!("\x1b[;96mcontinue?: \x1b[0m");
                if true {
                    let _ = std::io::stdout().flush();
                    let mut str = String::new();
                    let _ = std::io::stdin().read_line(&mut str);
                }
                println!();
            }

            // so we allocate a buffer for those on the stack here
            let mut inst_buf = [0u8; 15];
            // and read them from the current instruction pointer
            self.memory
                .read_to(Virtaddr(self.get_reg(Register::RIP)), &mut inst_buf)?;
            unsafe {
                IP = self.get_reg(Register::RIP);
                println!("{IP:#x}");
            };

            let instruction = Decoder::with_ip(
                64,
                &inst_buf,
                self.get_reg(Register::RIP),
                DecoderOptions::NO_INVALID_CHECK,
            )
            .decode();
            self.memory.read_to(Virtaddr(0x00474694), &mut inst_buf)?;

            // increments a register with a usize
            macro_rules! inc_reg {
                ($exp:expr, $reg:expr) => {
                    let new_val = $exp + self.get_reg::<usize, 8>($reg);
                    self.set_reg(new_val, $reg);
                };
            }
            // decrements a register with a usize
            macro_rules! dec_reg {
                ($exp:expr, $reg:expr) => {
                    let new_val = self.get_reg::<usize, 8>($reg) - $exp;
                    self.set_reg(new_val, $reg);
                };
            }
            macro_rules! pop {
                ($exp:expr) => {{
                    let sp: usize = self.get_reg::<usize, 8>(Register::RSP);
                    self.set_reg(sp + $exp as usize, Register::RSP);
                    self.memory.read_primitive(Virtaddr(sp))?
                }};
            }
            macro_rules! match_bitness_ts {
                ($id:ident) => {
                    match bitness(instruction, 0) {
                        Bitness::Eight => $id!(u8, 1),
                        Bitness::Sixteen => $id!(u16, 2),
                        Bitness::ThirtyTwo => $id!(u32, 4),
                        Bitness::SixtyFour => $id!(u64, 8),
                        Bitness::HundredTwentyEigth => $id!(u128, 16),
                    }
                };
            }
            macro_rules! match_bitness_typ {
                ($id:ident) => {
                    match bitness(instruction, 0) {
                        Bitness::Eight => $id!(u8),
                        Bitness::Sixteen => $id!(u16),
                        Bitness::ThirtyTwo => $id!(u32),
                        Bitness::SixtyFour => $id!(u64),
                        Bitness::HundredTwentyEigth => $id!(u128),
                    }
                };
            }
            macro_rules! match_bitness {
                ($id:ident, $bitness:expr) => {
                    match $bitness {
                        Bitness::Eight => $id!(u8),
                        Bitness::Sixteen => $id!(u16),
                        Bitness::ThirtyTwo => $id!(u32),
                        Bitness::SixtyFour => $id!(u64),
                        Bitness::HundredTwentyEigth => $id!(u128),
                    }
                };
            }

            macro_rules! jmp {
                () => {{
                    // get the new ip
                    let new_ip: u64 = self.get_val::<u64, 8>(instruction, 0)?;
                    self.set_reg(new_ip, Register::RIP);
                    // and jump to it
                    //                    continue 'next_instr;
                }};
            }

            macro_rules! sized_mov {
                ($typ:ty) => {{
                    let val: $typ = self.get_val(instruction, 1)?;
                    self.set_val(instruction, 0, val)?;
                }};
            }

            macro_rules! cc {
                (be,$code:expr) => {
                    if self.get_flag(Flag::ZF)
                        || self.get_flag(Flag::CF)
                    {
                        $code;
                    }
                };
                (ne,$code:expr) => {
                    if !self.get_flag(Flag::ZF) {
                        $code;
                    }
                };
                (e,$code:expr) => {
                    if self.get_flag(Flag::ZF) {
                        $code;
                    }
                };
                (b,$code:expr) => {
                    if self.get_flag(Flag::CF) {
                        $code;
                    }
                };
                (le,$code:expr) => {
                    // if the ZF==1
                    if self.get_flag(Flag::ZF)
                        // or SF!=OF
                        || (self.get_flag(Flag::SF) != self.get_flag(Flag::OF))
                    {
                        $code;
                    }
                };
                (l,$code:expr) => {
                    // if SF!=OF
                    if self.get_flag(Flag::SF) != self.get_flag(Flag::OF)
                    {
                        $code;
                    }
                };
                (g,$code:expr) => {
                    // if ZF==0
                    if !self.get_flag(Flag::ZF)
                        // and SF==OF
                        && (self.get_flag(Flag::SF) == self.get_flag(Flag::OF))
                    {
                        $code;
                    }
                };
                (a,$code:expr) => {
                    // if ZF==0
                    if !self.get_flag(Flag::ZF)
                        // and CF==0
                        && !self.get_flag(Flag::CF)
                    {
                        $code;
                    }
                };
                (ae,$code:expr) => {
                    // if CF==0
                    if !self.get_flag(Flag::CF) {
                        $code;
                    }
                };
                (s,$code:expr) => {
                    // if SF==1
                    if self.get_flag(Flag::SF) {
                        $code;
                    }
                };
                (ns,$code:expr) => {
                    // if SF==0
                    if !self.get_flag(Flag::SF) {
                        $code;
                    }
                }
            }

            // dbg!(instruction.mnemonic());

            // set the instruction pointer to the next instruction
            inc_reg!(instruction.len(), Register::RIP);
            // TODO: iced
            match instruction.mnemonic() {
                /*
                        +-------------------------+
                        | Arithmetic Instructions |
                        +-------------------------+
                */
                Mnemonic::Add => {
                    // add, as documented by https://www.felixcloutier.com/x86/add
                    macro_rules! sized_add {
                        ($typ:ty,$size:literal) => {{
                            let update_flags = |emu: &mut Emu, lhs: $typ, rhs: $typ, res: $typ| {
                                let lhs_msb = lhs.msb();
                                let rhs_msb = rhs.msb();
                                let res_msb = res.msb();

                                if lhs_msb == rhs_msb && res_msb != lhs_msb {
                                    emu.set_flag(Flag::OF)
                                } else {
                                    emu.unset_flag(Flag::OF)
                                }

                                if (lhs_msb && rhs_msb) || ((lhs_msb || rhs_msb) && !res_msb) {
                                    emu.set_flag(Flag::CF)
                                } else {
                                    emu.unset_flag(Flag::CF)
                                }

                                if (lhs & 0xf) + (rhs & 0xf) > 0xf {
                                    emu.set_flag(Flag::AuxCF)
                                } else {
                                    emu.unset_flag(Flag::AuxCF)
                                }
                            };
                            self.do_arith_op::<$typ, $typ, _, _, $size, $size>(
                                instruction,
                                <$typ>::wrapping_add,
                                update_flags,
                            )?
                        }};
                    }

                    match_bitness_ts!(sized_add);
                }
                Mnemonic::Sub => {
                    // sub, as documented by https://www.felixcloutier.com/x86/sub
                    macro_rules! sized_sub {
                        ($typ:ty,$size:literal) => {{
                            let update_flags = |emu: &mut Emu, lhs: $typ, rhs: $typ, res: $typ| {
                                let lhs_msb = lhs.msb();
                                let rhs_msb = rhs.msb();
                                let res_msb = res.msb();

                                if lhs_msb != rhs_msb && res_msb != lhs_msb {
                                    emu.set_flag(Flag::OF)
                                } else {
                                    emu.unset_flag(Flag::OF)
                                }

                                if lhs < rhs {
                                    emu.set_flag(Flag::CF)
                                } else {
                                    emu.unset_flag(Flag::CF)
                                }

                                if (lhs & 0xf) < (rhs & 0xf) {
                                    emu.set_flag(Flag::AuxCF)
                                } else {
                                    emu.unset_flag(Flag::AuxCF)
                                }
                            };
                            self.do_arith_op::<$typ, $typ, _, _, $size, $size>(
                                instruction,
                                <$typ>::wrapping_sub,
                                update_flags,
                            )?
                        }};
                    }

                    match_bitness_ts!(sized_sub)
                }
                Mnemonic::Sbb => {
                    macro_rules! sized_sbb {
                        ($typ:ty,$size:literal) => {{
                            let cf = self.get_flag(Flag::CF) as $typ;
                            let update_flags = |emu: &mut Emu, lhs: $typ, rhs: $typ, res: $typ| {
                                let rhs = rhs.wrapping_add(cf);

                                let lhs_msb = lhs.msb();
                                let rhs_msb = rhs.msb();
                                let res_msb = res.msb();

                                if lhs_msb != rhs_msb && res_msb != lhs_msb {
                                    emu.set_flag(Flag::OF)
                                } else {
                                    emu.unset_flag(Flag::OF)
                                }

                                if lhs < rhs {
                                    emu.set_flag(Flag::CF)
                                } else {
                                    emu.unset_flag(Flag::CF)
                                }

                                if (lhs & 0xf) < (rhs & 0xf) {
                                    emu.set_flag(Flag::AuxCF)
                                } else {
                                    emu.unset_flag(Flag::AuxCF)
                                }
                            };
                            self.do_arith_op::<$typ, $typ, _, _, $size, $size>(
                                instruction,
                                |lhs, rhs| {
                                    let rhs = rhs.wrapping_add(cf);
                                    lhs.wrapping_sub(rhs)
                                },
                                update_flags,
                            )?
                        }};
                    }

                    match_bitness_ts!(sized_sbb)
                }
                Mnemonic::Shr => {
                    // shr, as documented by https://www.felixcloutier.com/x86/sal:sar:shl:shr
                    macro_rules! sized_shr {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, $typ, _, $size, $size>(
                                instruction,
                                core::ops::Shr::shr,
                            )?
                        };
                    }

                    match_bitness_ts!(sized_shr)
                }
                Mnemonic::Sar => {
                    // sar, as documented by https://www.felixcloutier.com/x86/sal:sar:shl:shr
                    // as by https://www.reddit.com/r/rust/comments/2lp3il/where_is_arithmetic_signed_rightshift,
                    // we simply have to change our type to signed here
                    macro_rules! sized_shr {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, $typ, _, $size, $size>(
                                instruction,
                                core::ops::Shr::shr,
                            )?
                        };
                    }

                    match bitness(instruction, 0) {
                        Bitness::Eight => sized_shr!(i8, 1),
                        Bitness::Sixteen => sized_shr!(i16, 2),
                        Bitness::ThirtyTwo => sized_shr!(i32, 4),
                        Bitness::SixtyFour => sized_shr!(i64, 8),
                        Bitness::HundredTwentyEigth => sized_shr!(i128, 16),
                    }
                }
                Mnemonic::Shl => {
                    // shl, as documented by https://www.felixcloutier.com/x86/sal:sar:shl:shr

                    macro_rules! sized_shl {
                        ($typ:ty,$size:literal) => {{
                            let update_flags = |emu: &mut Emu, lhs: $typ, rhs: u8, res: $typ| {
                                let cf = lhs.wrapping_shl(rhs as u32 - 1).msb();
                                if rhs != 0 {
                                    if cf {
                                        emu.set_flag(Flag::CF);
                                    } else {
                                        emu.unset_flag(Flag::CF);
                                    }
                                }
                                if rhs == 1 {
                                    if res.msb() == cf {
                                        emu.unset_flag(Flag::OF);
                                    } else {
                                        emu.set_flag(Flag::OF);
                                    }
                                }
                                // TODO: deal with auxillary carry flag
                            };
                            self.do_arith_op::<$typ, u8, _, _, $size, 1>(
                                instruction,
                                |lhs, rhs| lhs.wrapping_shl(rhs as u32),
                                update_flags,
                            )?
                        }};
                    }

                    match_bitness_ts!(sized_shl)
                }
                Mnemonic::Imul => {
                    assert!(instruction.op_count() > 2);

                    // instruction.immediate(operand)

                    macro_rules! sized_imul {
                        ($typ:ty,$size:literal) => {{
                            let lhs: $typ = self.get_val(instruction, 1)?;
                            let rhs: $typ = match bitness(instruction, 2) {
                                Bitness::Eight => instruction.immediate(2) as i8 as $typ,
                                Bitness::Sixteen => instruction.immediate(2) as i16 as $typ,
                                Bitness::ThirtyTwo => instruction.immediate(2) as i32 as $typ,
                                Bitness::SixtyFour => instruction.immediate(2) as i64 as $typ,
                                x => unreachable!("{instruction}, bitness: {x:?}"),
                            };

                            let (res, of) = lhs.overflowing_mul(rhs);

                            self.set_val(instruction, 0, res)?;

                            if of {
                                self.set_flag(Flag::CF);
                                self.set_flag(Flag::OF);
                            } else {
                                self.unset_flag(Flag::CF);
                                self.unset_flag(Flag::OF);
                            }

                            self.unset_flag(Flag::SF);
                            self.unset_flag(Flag::ZF);
                            self.unset_flag(Flag::AuxCF);
                            self.unset_flag(Flag::PF);
                        }};
                    }

                    match bitness(instruction, 0) {
                        Bitness::Eight => todo!(),
                        Bitness::Sixteen => sized_imul!(i16, 2),
                        Bitness::ThirtyTwo => sized_imul!(i32, 4),
                        Bitness::SixtyFour => sized_imul!(i64, 8),
                        Bitness::HundredTwentyEigth => unreachable!("{instruction}"),
                    }
                }
                Mnemonic::Mul => {
                    // TODO: handle 8 bit case

                    macro_rules! sized_mul {
                        ($typ:ty,$size:literal) => {{
                            let lhs: $typ = self.get_reg(Register::RAX);
                            let rhs: $typ = self.get_val(instruction, 0)?;

                            let (rax, rdx) = lhs.widening_mul(rhs);

                            self.set_reg::<$typ, $size>(rax, Register::RAX);
                            self.set_reg::<$typ, $size>(rdx, Register::RDX);

                            if rdx == 0 {
                                self.unset_flag(Flag::CF);
                                self.unset_flag(Flag::OF);
                            } else {
                                self.set_flag(Flag::CF);
                                self.set_flag(Flag::OF);
                            }

                            // "SF, ZF, AF, and PF flags are undefined" (https://www.felixcloutier.com/x86/mul)

                            self.unset_flag(Flag::SF);
                            self.unset_flag(Flag::ZF);
                            self.unset_flag(Flag::AuxCF);
                            self.unset_flag(Flag::PF);
                        }};
                    }
                    match bitness(instruction, 0) {
                        Bitness::Eight => todo!(),
                        Bitness::Sixteen => sized_mul!(u16, 2),
                        Bitness::ThirtyTwo => sized_mul!(u32, 4),
                        Bitness::SixtyFour => sized_mul!(u64, 8),
                        Bitness::HundredTwentyEigth => unreachable!(),
                    }
                }
                Mnemonic::Idiv => {
                    // TODO: handle 8 bit case
                    // TODO: handle divide error
                    macro_rules! sized_idiv {
                        ($typ:ty,$size:literal,$double_typ:ty) => {{
                            let lhs: $double_typ = ((self.get_reg::<$typ, $size>(Register::RDX)
                                as $double_typ)
                                << ($size * 8))
                                | (self.get_reg::<$typ, $size>(Register::RAX) as $double_typ);
                            let rhs: $double_typ =
                                self.get_val::<$typ, $size>(instruction, 0)? as $double_typ;

                            self.set_reg::<$typ, $size>((lhs / rhs) as $typ, Register::RAX);
                            self.set_reg::<$typ, $size>((lhs % rhs) as $typ, Register::RDX);
                            // "CF, OF, SF, ZF, AF, and PF flags are undefined" (https://www.felixcloutier.com/x86/idiv)
                            self.unset_flag(Flag::CF);
                            self.unset_flag(Flag::OF);
                            self.unset_flag(Flag::SF);
                            self.unset_flag(Flag::ZF);
                            self.unset_flag(Flag::AuxCF);
                            self.unset_flag(Flag::PF);
                        }};
                    }
                    match bitness(instruction, 0) {
                        Bitness::Eight => todo!(),
                        Bitness::Sixteen => sized_idiv!(i16, 2, i32),
                        Bitness::ThirtyTwo => sized_idiv!(i32, 4, i64),
                        Bitness::SixtyFour => sized_idiv!(i64, 8, i128),
                        Bitness::HundredTwentyEigth => unreachable!(),
                    }
                }
                Mnemonic::Div => {
                    // div, as documented by https://www.felixcloutier.com/x86/div
                    // TODO: handle divide error
                    // TODO: handle 8 bit case
                    macro_rules! sized_div {
                        ($typ:ty,$size:literal,$double_typ:ty) => {{
                            let lhs: $double_typ = ((self.get_reg::<$typ, $size>(Register::RDX)
                                as $double_typ)
                                << ($size * 8))
                                | (self.get_reg::<$typ, $size>(Register::RAX) as $double_typ);
                            let rhs: $double_typ =
                                self.get_val::<$typ, $size>(instruction, 0)? as $double_typ;
                            self.set_reg::<$typ, $size>((lhs / rhs) as $typ, Register::RAX);
                            self.set_reg::<$typ, $size>((lhs % rhs) as $typ, Register::RDX);
                            // "CF, OF, SF, ZF, AF, and PF flags are undefined" (https://www.felixcloutier.com/x86/div)
                            self.unset_flag(Flag::CF);
                            self.unset_flag(Flag::OF);
                            self.unset_flag(Flag::SF);
                            self.unset_flag(Flag::ZF);
                            self.unset_flag(Flag::AuxCF);
                            self.unset_flag(Flag::PF);
                        }};
                    }
                    match bitness(instruction, 0) {
                        Bitness::Eight => todo!(),
                        Bitness::Sixteen => sized_div!(u16, 2, u32),
                        Bitness::ThirtyTwo => sized_div!(u32, 4, u64),
                        Bitness::SixtyFour => sized_div!(u64, 8, u128),
                        Bitness::HundredTwentyEigth => unreachable!(),
                    }
                }

                /*
                        +----------------------+
                        | Logical Instructions |
                        +----------------------+
                */
                Mnemonic::And => {
                    // as documented by https://www.felixcloutier.com/x86/and
                    macro_rules! sized_and {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, $typ, _, $size, $size>(
                                instruction,
                                core::ops::BitAnd::bitand,
                            )?
                        };
                    }

                    match_bitness_ts!(sized_and)
                }
                Mnemonic::Bsf => {
                    // as documented by https://www.felixcloutier.com/x86/bsf
                    macro_rules! sized_bsf {
                        ($typ:ty) => {{
                            //  The CF, OF, SF, AF, and PF flags are undefined.
                            let source: $typ = self.get_val(instruction, 1)?;

                            self.unset_flag(Flag::CF);
                            self.unset_flag(Flag::OF);
                            self.unset_flag(Flag::SF);
                            self.unset_flag(Flag::AuxCF);
                            self.unset_flag(Flag::PF);

                            if source == 0 {
                                self.set_flag(Flag::ZF);
                            } else {
                                self.unset_flag(Flag::ZF);
                                self.set_val(instruction, 0, source.trailing_zeros() as $typ)?;
                            }
                        }};
                    }

                    match_bitness_typ!(sized_bsf)
                }
                Mnemonic::Bsr => {
                    // as documented by https://www.felixcloutier.com/x86/bsr
                    macro_rules! sized_bsr {
                        ($typ:ty) => {{
                            //  The CF, OF, SF, AF, and PF flags are undefined.
                            let source: $typ = self.get_val(instruction, 1)?;

                            self.unset_flag(Flag::CF);
                            self.unset_flag(Flag::OF);
                            self.unset_flag(Flag::SF);
                            self.unset_flag(Flag::AuxCF);
                            self.unset_flag(Flag::PF);

                            if source == 0 {
                                self.set_flag(Flag::ZF);
                            } else {
                                self.unset_flag(Flag::ZF);
                                self.set_val(instruction, 0, source.leading_zeros() as $typ)?;
                            }
                        }};
                    }

                    match_bitness_typ!(sized_bsr)
                }
                Mnemonic::Xor => {
                    // xor, as documented by https://www.felixcloutier.com/x86/xor
                    macro_rules! sized_xor {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, $typ, _, $size, $size>(
                                instruction,
                                core::ops::BitXor::bitxor,
                            )?
                        };
                    }

                    match_bitness_ts!(sized_xor);
                    self.unset_flag(Flag::CF);
                    self.unset_flag(Flag::OF);
                }
                Mnemonic::Not => {
                    macro_rules! sized_not {
                        ($typ:ty) => {{
                            let val: $typ = self.get_val(instruction, 0)?;
                            let res = !val;

                            self.set_val(instruction, 0, res)?;
                        }};
                    }

                    match_bitness_typ!(sized_not)
                }
                Mnemonic::Neg => {
                    macro_rules! sized_neg {
                        ($typ:ty) => {{
                            let val: $typ = self.get_val(instruction, 0)?;

                            if val == 0 {
                                self.unset_flag(Flag::CF)
                            } else {
                                self.set_flag(Flag::CF)
                            }

                            let res = (!val).wrapping_add(1);
                            self.set_common_flags(res);

                            self.set_val(instruction, 0, res)?;
                        }};
                    }

                    match_bitness_typ!(sized_neg)
                }
                Mnemonic::Or => {
                    // or, as documented by https://www.felixcloutier.com/x86/or
                    macro_rules! sized_or {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, $typ, _, $size, $size>(
                                instruction,
                                core::ops::BitOr::bitor,
                            )?
                        };
                    }

                    match_bitness_ts!(sized_or)
                }
                Mnemonic::Cqo => {
                    let rdx = self.get_reg::<u64, 8>(Register::RAX).msb() as u64 * u64::MAX;
                    self.set_reg(rdx, Register::RDX);
                }
                Mnemonic::Cdqe => {
                    let val = self.get_reg::<i32, 4>(Register::RAX) as i64;
                    self.set_reg(val, Register::RAX);
                }

                Mnemonic::Rol => {
                    // rol https://www.felixcloutier.com/x86/rcl:rcr:rol:ror

                    macro_rules! sized_rol {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, u32, _, $size, 4>(instruction, |lhs, rhs| {
                                if $size == 8 {
                                    lhs.rotate_left(rhs & 0b111111)
                                } else {
                                    lhs.rotate_left(rhs & 0b11111)
                                }
                            })?
                        };
                    }

                    match_bitness_ts!(sized_rol)
                }

                Mnemonic::Ror => {
                    // ror https://www.felixcloutier.com/x86/rcl:rcr:rol:ror

                    macro_rules! sized_ror {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, u32, _, $size, 4>(instruction, |lhs, rhs| {
                                if $size == 8 {
                                    lhs.rotate_right(rhs & 0b111111)
                                } else {
                                    lhs.rotate_right(rhs & 0b11111)
                                }
                            })?
                        };
                    }

                    match_bitness_ts!(sized_ror)
                }

                /*
                        +---------------------------+
                        | Control Flow Instructions |
                        +---------------------------+
                */
                // | function  instructions |
                Mnemonic::Call => {
                    // call as documented by https://www.felixcloutier.com/x86/call
                    // get the new ip

                    let new_ip: usize = self.get_val::<usize, 8>(instruction, 0)?;
                    #[cfg(debug_assertions)]
                    {
                        call_depth += 1;
                        let sym = self.memory.get_sym(new_ip);
                        println!(
                            "{:\t<1$}{sym} called from: {ip:#x}",
                            "",
                            call_depth,
                            ip = self.get_reg::<usize, 8>(Register::RIP)
                        );
                    }
                    // push our old ip onto the stack
                    self.push(self.get_reg::<u64, 8>(Register::RIP));
                    // set rip to the new ip and continue execution there
                    self.set_reg(new_ip, Register::RIP);
                }
                Mnemonic::Ret => {
                    // get the new ip
                    let new_ip: u64 = {
                        let sp: usize = self.get_reg::<usize, 8>(Register::RSP);
                        self.set_reg(sp + 8usize, Register::RSP);
                        self.memory.read_primitive(Virtaddr(sp))?
                    };
                    println!("new IP: {new_ip:#x}");
                    #[cfg(debug_assertions)]
                    {
                        println!(
                            "{:\t<1$}⮡ {rax:#x}",
                            "",
                            call_depth,
                            rax = self.get_reg::<usize, 8>(Register::RAX)
                        );
                        call_depth -= 1;
                    }
                    self.set_reg(new_ip, Register::RIP);
                }

                // | jump instructions |
                Mnemonic::Jne => {
                    cc! {ne,
                        jmp!()
                    }
                }
                Mnemonic::Jbe => {
                    cc! {be,
                        jmp!()
                    }
                }
                Mnemonic::Je => {
                    cc! {e,
                        jmp!()
                    }
                }
                Mnemonic::Jb => {
                    cc! {b,
                        jmp!()
                    }
                }
                Mnemonic::Jl => {
                    cc! { l,
                        jmp!()
                    }
                }
                Mnemonic::Jle => {
                    cc! { le,
                        jmp!()
                    }
                }
                Mnemonic::Jg => {
                    cc! {g,
                        jmp!()
                    }
                }
                Mnemonic::Ja => {
                    cc! {a,
                        jmp!()
                    }
                }
                Mnemonic::Jae => {
                    cc! { ae,
                        jmp!()
                    }
                }
                Mnemonic::Js => {
                    cc! { s,
                        jmp!()
                    }
                }
                Mnemonic::Jns => {
                    cc! { ns,
                        jmp!()
                    }
                }
                Mnemonic::Jmp => {
                    jmp!();
                }

                // | FLAGS setting instructions |
                Mnemonic::Cmp => {
                    macro_rules! cmp_with_type {
                        ($typ:ty) => {{
                            let lhs: $typ = self.get_val(instruction, 0)?;
                            let rhs: $typ = self.get_val(instruction, 1)?;
                            let res = lhs.wrapping_sub(rhs);

                            let lhs_msb = lhs.msb();
                            let rhs_msb = rhs.msb();
                            let res_msb = res.msb();

                            if lhs_msb != rhs_msb && res_msb != lhs_msb {
                                self.set_flag(Flag::OF)
                            } else {
                                self.unset_flag(Flag::OF)
                            }

                            if lhs < rhs {
                                self.set_flag(Flag::CF)
                            } else {
                                self.unset_flag(Flag::CF)
                            }

                            if (lhs & 0xf) < (rhs & 0xf) {
                                self.set_flag(Flag::AuxCF)
                            } else {
                                self.unset_flag(Flag::AuxCF)
                            }
                            self.set_common_flags(res);
                        }};
                    }

                    match_bitness_typ!(cmp_with_type)
                }
                Mnemonic::Test => {
                    let lhs: u64 = self.get_val(instruction, 0)?;
                    let rhs: u64 = self.get_val(instruction, 1)?;
                    let and_res: u64 = lhs & rhs;
                    let bitness = bitness(instruction, 0);
                    if (and_res & (1 << (bitness as u64 - 1))) > 0 {
                        self.set_flag(Flag::SF)
                    } else {
                        self.unset_flag(Flag::SF)
                    }
                    self.unset_flag(Flag::OF);
                    self.unset_flag(Flag::CF);
                    if and_res == 0 {
                        self.set_flag(Flag::ZF);
                    } else {
                        self.unset_flag(Flag::ZF);
                    }
                    if (and_res & 0xff).count_ones() & 1 == 0 {
                        self.set_flag(Flag::PF);
                    } else {
                        self.unset_flag(Flag::PF);
                    }
                }

                /*
                        +----------------------+
                        | *mov*   Instructions |
                        +----------------------+
                */
                Mnemonic::Cmovne => {
                    cc! {ne,
                        match_bitness_typ!(sized_mov)
                    }
                }
                Mnemonic::Cmove => {
                    cc! {e,
                        match_bitness_typ!(sized_mov)
                    }
                }
                Mnemonic::Cmova => {
                    cc! {a,
                        match_bitness_typ!(sized_mov)
                    }
                }
                Mnemonic::Cmovae => {
                    cc! {ae,
                        match_bitness_typ!(sized_mov)
                    }
                }
                Mnemonic::Cmovbe => {
                    cc! {be,
                        match_bitness_typ!(sized_mov)
                    }
                }
                Mnemonic::Cmovg => {
                    cc! {g,
                        match_bitness_typ!(sized_mov)
                    }
                }
                Mnemonic::Cmovb => {
                    cc! {b,
                        match_bitness_typ!(sized_mov)
                    }
                }
                Mnemonic::Cmpxchg => {
                    let op1 = instruction.op1_register();
                    let bitness = reg_bitness(op1);

                    macro_rules! sized_cmpxchg {
                        ($typ:ty) => {{
                            let op0 = self.get_val(instruction, 0).unwrap();
                            let rax: $typ = self.get_reg(Register::RAX);
                            if rax == op0 {
                                let reg = reg_from_iced_reg(op1).unwrap();
                                let reg_val: $typ = self.get_reg(reg);
                                self.set_val(instruction, 0, reg_val).unwrap();
                                // self.set_reg(op0, reg);
                                self.set_flag(Flag::ZF);
                            } else {
                                self.set_reg(op0, Register::RAX);
                                self.unset_flag(Flag::ZF);
                            }
                        }};
                    }

                    match_bitness!(sized_cmpxchg, bitness);
                }
                Mnemonic::Mov => {
                    // mov, as documented by https://www.felixcloutier.com/x86/mov
                    match_bitness_typ!(sized_mov)
                }
                Mnemonic::Movd => {
                    sized_mov!(u32)
                }
                Mnemonic::Movq => {
                    sized_mov!(u64)
                }
                Mnemonic::Movsxd => {
                    // movsxd, as documented by https://www.felixcloutier.com/x86/movsx:movsxd

                    match bitness(instruction, 0) {
                        Bitness::Eight => unreachable!(),
                        Bitness::Sixteen => match bitness(instruction, 1) {
                            Bitness::Eight => {
                                let val: i8 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val as i16)?;
                            }
                            Bitness::Sixteen => {
                                let val: i16 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val)?;
                            }
                            _ => unreachable!(),
                        },
                        Bitness::ThirtyTwo => match bitness(instruction, 1) {
                            Bitness::Eight => {
                                let val: i8 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val as i32)?;
                            }
                            Bitness::Sixteen => {
                                let val: i16 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val as i32)?;
                            }
                            Bitness::ThirtyTwo => {
                                let val: i32 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val)?;
                            }
                            _ => unreachable!(),
                        },
                        Bitness::SixtyFour => match bitness(instruction, 1) {
                            Bitness::Eight => {
                                let val: i8 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val as i64)?;
                            }
                            Bitness::Sixteen => {
                                let val: i16 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val as i64)?;
                            }
                            Bitness::ThirtyTwo => {
                                let val: i32 = self.get_val(instruction, 1)?;
                                self.set_val(instruction, 0, val as i64)?;
                            }
                            x => unreachable!("{instruction}, bittnes: {x:?}"),
                        },
                        Bitness::HundredTwentyEigth => unreachable!(),
                    }
                }
                Mnemonic::Movzx => match bitness(instruction, 0) {
                    Bitness::Eight => unreachable!(),
                    Bitness::Sixteen => match bitness(instruction, 1) {
                        Bitness::Eight => {
                            let val: u8 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val as u16)?;
                        }
                        Bitness::Sixteen => {
                            let val: u16 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val)?;
                        }
                        _ => unreachable!(),
                    },
                    Bitness::ThirtyTwo => match bitness(instruction, 1) {
                        Bitness::Eight => {
                            let val: u8 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val as u32)?;
                        }
                        Bitness::Sixteen => {
                            let val: u16 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val as u32)?;
                        }
                        Bitness::ThirtyTwo => {
                            let val: u32 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val)?;
                        }
                        _ => unreachable!(),
                    },
                    Bitness::SixtyFour => match bitness(instruction, 1) {
                        Bitness::Eight => {
                            let val: u8 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val as u64)?;
                        }
                        Bitness::Sixteen => {
                            let val: u16 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val as u64)?;
                        }
                        Bitness::ThirtyTwo => {
                            let val: u32 = self.get_val(instruction, 1)?;
                            self.set_val(instruction, 0, val as u64)?;
                        }
                        x => unreachable!("{instruction}, bittnes: {x:?}"),
                    },
                    Bitness::HundredTwentyEigth => unreachable!(),
                },
                /*
                        +----------------------+
                        | Stack   Instructions |
                        +----------------------+
                */
                Mnemonic::Pop => {
                    macro_rules! pop_sized {
                        ($typ:ty, $size:literal) => {{
                            let val: $typ = pop!($size);
                            self.set_val(instruction, 0, val)?;
                        }};
                    }
                    match_bitness_ts!(pop_sized)
                }
                Mnemonic::Push => {
                    macro_rules! push_sized {
                        ($typ:ty) => {{
                            let val: $typ = self.get_val(instruction, 0)?;
                            self.push(val);
                        }};
                    }

                    match_bitness_typ!(push_sized)
                }
                Mnemonic::Pushfq => {
                    self.push(self.rflags);
                }
                Mnemonic::Rdsspq => {
                    self.set_val(
                        instruction,
                        0,
                        0, // self.get_reg::<u64, 8>(Register::RSP)
                    )?;
                }
                /*
                        +-----------------------------+
                        | Miscellaneous  Instructions |
                        +-----------------------------+
                */
                Mnemonic::Cpuid => {
                    // pretend we're a very old cpu
                    // https://de.wikipedia.org/wiki/CPUID
                    // dbg!();
                    let ax = self.get_reg::<u8, 1>(Register::RAX);
                    if ax == 0 {
                        unsafe {
                            self.set_reg(
                                std::mem::transmute::<[u8; 4], u32>(*b"DMAc"),
                                Register::RBX,
                            );
                        }
                        unsafe {
                            self.set_reg(
                                std::mem::transmute::<[u8; 4], u32>(*b"itne"),
                                Register::RDX,
                            );
                        }
                        unsafe {
                            self.set_reg(
                                std::mem::transmute::<[u8; 4], u32>(*b"htuA"),
                                Register::RCX,
                            );
                        }
                    } else if ax == 1 {
                        self.set_reg(0, Register::RCX);
                        self.set_reg(
                            (1 << 26) | (1 << 25) | (1 << 15) | (1 << 11) | (1 << 29),
                            Register::RDX,
                        );
                    } else {
                        todo!()
                    }
                }
                Mnemonic::Endbr64 => {
                    // do nothing here for now
                }
                Mnemonic::Nop => {
                    // it's literally a Nop
                }
                Mnemonic::Lea => {
                    // calling set_val and matching is overkill here
                    // so TODO: inline the set_reg call performed here
                    self.set_val(instruction, 0, self.calc_addr(instruction))?;
                }
                Mnemonic::Xchg => {
                    macro_rules! sized_xchg {
                        ($typ:ty) => {{
                            let val0: $typ = self.get_val(instruction, 0).unwrap();
                            let val1: $typ = self.get_val(instruction, 1).unwrap();
                            self.set_val(instruction, 0, val1).unwrap();
                            self.set_val(instruction, 1, val0).unwrap();
                        }};
                    }
                    match_bitness_typ!(sized_xchg);
                }
                /*
                        +-------------------------+
                        | String     Instructions |
                        +-------------------------+
                */
                Mnemonic::Stosq => {
                    let base_addr: usize = self.get_reg(Register::RDI);
                    let rax_val: u64 = self.get_reg(Register::RAX);
                    if instruction.has_rep_prefix() {
                        loop {
                            let index: usize = self.get_reg(Register::RCX);

                            self.memory
                                .write_primitive(Virtaddr(index * 8 + base_addr), rax_val)?;
                            if self.get_reg::<usize, 8>(Register::RCX) == 0 {
                                continue 'next_instr;
                            }
                            dec_reg!(1, Register::RCX);
                        }
                    } else {
                        todo!()
                    }
                }
                Mnemonic::Sete => {
                    self.set_val(instruction, 0, self.get_flag(Flag::ZF) as u8)?;
                }
                Mnemonic::Setne => {
                    self.set_val(instruction, 0, !self.get_flag(Flag::ZF) as u8)?;
                }
                Mnemonic::Seto => {
                    self.set_val(instruction, 0, self.get_flag(Flag::OF) as u8)?;
                }
                /*
                        +----------------------+
                        | SIMD    Instructions |
                        +----------------------+
                */
                Mnemonic::Punpckldq => {
                    let lhs: u32x4 =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 0)?) };
                    let rhs =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 1)?) };

                    let val: u128 = unsafe { core::mem::transmute(lhs.interleave(rhs).0) };

                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Punpcklqdq => {
                    let lhs: u64x2 =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 0)?) };
                    let rhs =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 1)?) };

                    let val: u128 = unsafe { core::mem::transmute(lhs.interleave(rhs).0) };

                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Punpcklbw => {
                    let lhs: u8x16 =
                        u8x16::from_array(self.get_val::<u128, 16>(instruction, 0)?.to_ne_bytes());
                    let rhs: u8x16 =
                        u8x16::from_array(self.get_val::<u128, 16>(instruction, 1)?.to_ne_bytes());

                    let val: u128 = unsafe { core::mem::transmute(lhs.interleave(rhs).0) };

                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Punpcklwd => {
                    let lhs: u16x8 =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 0)?) };
                    let rhs =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 1)?) };

                    let val: u128 = unsafe { core::mem::transmute(lhs.interleave(rhs).0) };

                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Movaps | Mnemonic::Movdqa | Mnemonic::Movups | Mnemonic::Movdqu => {
                    let val: u128 = self.get_val(instruction, 1)?;
                    self.set_val(instruction, 0, val).unwrap();
                }
                Mnemonic::Movhps => {
                    let src: u128 = self.get_val::<u64, 8>(instruction, 1)? as u128;
                    self.set_val(instruction, 1, (src << 64) as u64)?;
                }
                Mnemonic::Pshufd => {
                    let imm = instruction.immediate8();
                    let bite1 = imm & 0b11;
                    let bite2 = (imm >> 2) & 0b11;
                    let bite3 = (imm >> 4) & 0b11;
                    let bite4 = (imm >> 6) & 0b11;

                    let src: u8x16 =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 1)?) };

                    let idxs = Simd::from_array([bite1, bite2, bite3, bite4]);
                    // hack our way around rust's swizzle's limits
                    let v1 = simd_swizzle!(src, [0, 4, 8, 12]);
                    let v2 = simd_swizzle!(src, [1, 5, 9, 13]);
                    let v3 = simd_swizzle!(src, [2, 6, 10, 14]);
                    let v4 = simd_swizzle!(src, [3, 7, 11, 15]);

                    let shuf1 = v1.swizzle_dyn(idxs);
                    let shuf2 = v2.swizzle_dyn(idxs);
                    let shuf3 = v3.swizzle_dyn(idxs);
                    let shuf4 = v4.swizzle_dyn(idxs);

                    let shuf12: u8x8 = unsafe { core::mem::transmute(shuf1.interleave(shuf2)) };
                    let shuf34: u8x8 = unsafe { core::mem::transmute(shuf3.interleave(shuf4)) };

                    let shuf: u128 = unsafe { core::mem::transmute(shuf12.interleave(shuf34)) };

                    self.set_val(instruction, 0, shuf)?;
                }
                Mnemonic::Pxor => {
                    let lhs: u128 = self.get_val(instruction, 0)?;
                    let rhs: u128 = self.get_val(instruction, 1)?;

                    self.set_val(instruction, 0, lhs ^ rhs)?;
                }
                Mnemonic::Pand => {
                    let lhs: u128 = self.get_val(instruction, 0)?;
                    let rhs: u128 = self.get_val(instruction, 1)?;

                    self.set_val(instruction, 0, lhs & rhs)?;
                }
                Mnemonic::Pcmpeqb => {
                    let lhs: u8x16 =
                        u8x16::from_array(self.get_val::<u128, 16>(instruction, 0)?.to_ne_bytes());
                    let rhs: u8x16 =
                        u8x16::from_array(self.get_val::<u128, 16>(instruction, 1)?.to_ne_bytes());

                    let val: u128 = unsafe { core::mem::transmute(lhs.simd_eq(rhs).to_int()) };

                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Pcmpeqd => {
                    let lhs: u32x4 =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 0)?) };
                    let rhs =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 1)?) };

                    let val: u128 = unsafe { core::mem::transmute(lhs.simd_eq(rhs).to_int()) };

                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Pmovmskb => {
                    let int: i8x16 =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 1)?) };
                    let mask: u64 = unsafe { Mask::from_int_unchecked(int).to_bitmask() };
                    self.set_val(instruction, 0, mask)?;
                }
                Mnemonic::Pminub => {
                    let lhs: u8x16 =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 0)?) };
                    let rhs =
                        unsafe { core::mem::transmute(self.get_val::<u128, 16>(instruction, 1)?) };

                    let val: u128 = unsafe { core::mem::transmute(lhs.simd_min(rhs)) };

                    self.set_val(instruction, 0, val)?;
                }
                /*
                        +---------------------------------+
                        | Kernel interfacing Instructions |
                        +---------------------------------+
                */
                Mnemonic::Syscall => {
                    self.handle_syscall(self.get_reg(Register::RAX))?;
                }
                x => unsafe {
                    todo!(
                        "unsupported opcode: {x:?} at IP {IP:#x} and SP {:#x}",
                        self.get_reg::<usize, 8>(Register::RSP)
                    )
                },
            };
        }
    }

    fn handle_syscall(&mut self, nr: usize) -> Result<()> {
        // TODO: lots of syscalls here are implemented accordind to their libc wrappers
        // TODO: implement them according to the linux kernel implementation
        match nr {
            // write
            1 => {
                // get the bytes passed to write
                let addr: u64 = self.get_reg(Register::RSI);
                let size: u64 = self.get_reg(Register::RDX);
                let bytes = self
                    .memory
                    .peek(Virtaddr(addr as usize), size as usize, PERM_READ)?;
                // if we're dealing with stdout or stderr
                if self.get_reg::<u64, 8>(Register::RDI) == 2
                    || self.get_reg::<u64, 8>(Register::RDI) == 1
                {
                    // first convert the given memory to a string
                    // unwrap here for now
                    let str = std::str::from_utf8(bytes).unwrap();
                    // simply print this for now
                    println!("{str}");
                } else {
                    todo!()
                }
                self.set_reg(0u64, Register::RAX)
            }
            // mmap
            9 => {
                let rdi: u64 = self.get_reg(Register::RDI);
                if rdi == 0 {
                    let rsi = self.get_reg::<u64, 8>(Register::RSI);
                    if let Some((Virtaddr(addr), _)) = self.memory.allocate(rsi as usize) {
                        self.set_reg(addr, Register::RAX)
                    }
                    // allocating memory failed
                    else {
                        self.set_reg(u64::MAX, Register::RAX)
                    }
                } else {
                    todo!()
                }
            }
            // mprotect
            10 => {
                let start = Virtaddr(self.get_reg(Register::RDI));
                let len: usize = self.get_reg(Register::RSI);
                let prot: u8 = self.get_reg(Register::RDX);
                let read = (prot & 0x1) << 2;
                let write = prot & 0x2;
                let exec = (prot & 0x4) >> 2;

                let perms = Perm(read | write | exec);

                // panic!("{perms:?}");

                self.memory.set_permissions(start, len, perms)?;

                self.set_reg(0u64, Register::RAX);
            }
            // brk
            12 => {
                let rdi: u64 = self.get_reg(Register::RDI);
                if rdi == 0 {
                    self.set_reg(self.memory.cur_alc.0, Register::RAX);
                } else {
                    // ignore deallocations for now
                    if let Some((_, addr)) =
                        self.memory.allocate(rdi as usize - self.memory.cur_alc.0)
                    {
                        self.set_reg(addr.0, Register::RAX)
                    }
                    // allocating memory failed
                    else {
                        self.set_reg(-1i64, Register::RAX)
                    }
                }
            }
            // access
            21 => {
                // pretend you can
                self.set_reg(0, Register::RAX)
            }
            // exit
            60 => {
                let code = self.get_reg(Register::RDI);
                return Err(ExecErr::Exit {
                    code,
                    ip: unsafe { IP },
                });
            }
            // arch_prctl
            158 => {
                match self.get_reg::<u64, 8>(Register::RDI) {
                    // ARCH_SET_GS
                    0x1001 => {
                        todo!("SET_GS")
                    }
                    // ARCH_SET_FS
                    0x1002 => {
                        let addr = self.get_reg(Register::RSI);
                        self.set_seg(SegReg::Fs, addr);
                        self.memory.write_primitive(Virtaddr(addr as usize), addr)?;
                        // we were succesful
                        self.set_reg(0u64, Register::RAX)
                    }
                    // ARCH_GET_GS
                    0x1003 => {
                        todo!("GET_GS")
                    }
                    // ARCH_GET_FS
                    0x1004 => {
                        todo!("GET_FS")
                    }
                    // ARCH_GET_CPUID
                    0x1011 => {
                        todo!("GET_CPUID")
                    }
                    // ARCH_SET_CPUID
                    0x1012 => {
                        todo!("GET_CPUID")
                    }
                    // EINVAL
                    _ => self.set_reg(u64::MAX, Register::RAX),
                }
            }
            // set_tid_address
            218 => {
                // do nothing for now
                self.set_reg(1000u64, Register::RAX)
            }
            // clock_gettime
            228 => {
                let addr: usize = self.get_reg(Register::RSI);
                let time: u64 = self.rng();
                self.memory.write_primitive(Virtaddr(addr), time).unwrap();
                self.memory
                    .write_primitive(Virtaddr(addr + 8), time * 1_000_000_000)
                    .unwrap();
                self.set_reg(0u64, Register::RAX)
            }
            // set_robust_list
            273 => {
                // do nothing for now
                self.set_reg(0u64, Register::RAX)
            }
            // exit
            231 => {
                let code = self.get_reg(Register::RDI);
                return Err(ExecErr::Exit {
                    code,
                    ip: unsafe { IP },
                });
            }
            // readlinkat
            267 => {
                let bufsize: u64 = self.get_reg(Register::R10);
                let path_ptr: u64 = self.get_reg(Register::RSI);
                let path = self
                    .memory
                    .read_cstr(Virtaddr(path_ptr as usize), bufsize as usize)
                    .to_vec();
                // if the application asked for its own path
                if &path == b"/proc/self/exe" {
                    let path = b"/bin/test";
                    let buf: usize = self.get_reg(Register::RDX);
                    self.memory.write_from(Virtaddr(buf), path).unwrap();
                    self.set_reg(path.len(), Register::RAX);
                    return Ok(());
                }
                let buf: usize = self.get_reg(Register::RDX);
                self.memory.write_from(Virtaddr(buf), &path).unwrap();
                self.set_reg(path.len(), Register::RAX);
            }
            // prlimit
            302 => {
                // say we succeded
                self.set_reg(0u64, Register::RAX)
            }
            // getrandom
            318 => {
                let buf: usize = self.get_reg(Register::RDI);
                let count: usize = self.get_reg(Register::RSI);
                for idx in 0..count {
                    self.memory
                        .write_primitive(Virtaddr(buf + idx), self.rng)
                        .unwrap();
                }
            }
            // rseq
            334 => {
                // do nothing for now
                self.set_reg(0u64, Register::RAX)
            }
            x => todo!("syscall # {x}"),
        };
        Ok(())
    }
    /// perform a logical operation, given by `f`,on the given operands
    #[inline]
    pub fn do_loar_op<
        T: Primitive<BYTES>,
        T1: Primitive<BYTES1>,
        F: FnMut(T, T1) -> T,
        const BYTES: usize,
        const BYTES1: usize,
    >(
        &mut self,
        instruction: Instruction,
        mut f: F,
    ) -> Result<()>
    where
        <T as TryFrom<u8>>::Error: Debug,
        <T as TryFrom<u16>>::Error: Debug,
        <T as TryFrom<u32>>::Error: Debug,
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
        <T as TryInto<u16>>::Error: Debug,
        <T as TryInto<u32>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
        <T1 as TryFrom<u8>>::Error: Debug,
        <T1 as TryFrom<u16>>::Error: Debug,
        <T1 as TryFrom<u32>>::Error: Debug,
        <T1 as TryFrom<u64>>::Error: Debug,
        <T1 as TryFrom<u128>>::Error: Debug,
        <T1 as TryInto<u16>>::Error: Debug,
        <T1 as TryInto<u32>>::Error: Debug,
        <T1 as TryInto<u64>>::Error: Debug,
        <T1 as TryInto<u128>>::Error: Debug,
    {
        let rhs: T1 = self.get_val::<T1, BYTES1>(instruction, 1)?;
        let lhs: T = self.get_val::<T, BYTES>(instruction, 0)?;
        let res = f(lhs, rhs);

        self.set_common_flags(res);

        self.unset_flag(Flag::OF);
        self.unset_flag(Flag::CF);

        self.set_val(instruction, 0, res)
    }

    /// perform a arithmetic operation, given by `f`,on the given operands
    /// first updates common arithmetic rflags and then updates the with the
    /// supplied function `update_fags` gets run afterward
    #[inline]
    pub fn do_arith_op<
        T: Primitive<BYTES>,
        T1: Primitive<BYTES1>,
        F: FnMut(T, T1) -> T,
        U: FnMut(&mut Emu, T, T1, T),
        const BYTES: usize,
        const BYTES1: usize,
    >(
        &mut self,
        instruction: Instruction,
        mut f: F,
        mut update_flags: U,
    ) -> Result<()>
    where
        <T as TryFrom<u8>>::Error: Debug,
        <T as TryFrom<u16>>::Error: Debug,
        <T as TryFrom<u32>>::Error: Debug,
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
        <T as TryInto<u16>>::Error: Debug,
        <T as TryInto<u32>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
        T: std::ops::Shr<usize, Output = T>,
        <T1 as TryFrom<u8>>::Error: Debug,
        <T1 as TryFrom<u16>>::Error: Debug,
        <T1 as TryFrom<u32>>::Error: Debug,
        <T1 as TryFrom<u64>>::Error: Debug,
        <T1 as TryFrom<u128>>::Error: Debug,
        <T1 as TryInto<u16>>::Error: Debug,
        <T1 as TryInto<u32>>::Error: Debug,
        <T1 as TryInto<u64>>::Error: Debug,
        <T1 as TryInto<u128>>::Error: Debug,
    {
        // TODO: make the caller responsible for giving the right operands
        let rhs: T1 = self.get_val::<T1, BYTES1>(instruction, 1)?;
        let lhs: T = self.get_val::<T, BYTES>(instruction, 0)?;
        let res = f(lhs, rhs);

        self.set_common_flags(res);

        update_flags(self, lhs, rhs, res);

        self.set_val(instruction, 0, res)
    }

    fn set_common_flags<const SIZE: usize>(&mut self, res: impl Primitive<SIZE>) {
        let pf = (res.count_ones() & 1) == 0;
        let sf = res.msb();
        let zf = res.is_zero();

        if pf {
            self.set_flag(Flag::PF)
        } else {
            self.unset_flag(Flag::PF)
        }
        if sf {
            self.set_flag(Flag::SF)
        } else {
            self.unset_flag(Flag::SF)
        }
        if zf {
            self.set_flag(Flag::ZF)
        } else {
            self.unset_flag(Flag::ZF)
        }
    }

    /// set an operand to a value.
    /// this will fail if we try writing to a memory region without the correct
    /// permissions
    #[inline]
    fn set_val<T: Primitive<BYTES>, const BYTES: usize>(
        &mut self,
        instruction: Instruction,
        index: u32,
        val: T,
    ) -> Result<()>
    where
        <T as TryInto<u16>>::Error: Debug,
        <T as TryInto<u32>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        let opkind = instruction.op_kind(index);
        match opkind {
            OpKind::Register => {
                let reg: Register = reg_from_iced_reg(instruction.op_register(index)).unwrap();
                self.set_reg(val, reg);
                Ok(())
            }
            OpKind::Memory => {
                let address: usize = self.calc_addr(instruction);
                Ok(self.memory.write_primitive(Virtaddr(address), val)?)
            }
            _ => unreachable!(),
        }
    }

    #[inline]
    /// resolve the address an instruction uses
    // XXX: I think there only can be one such operand
    fn calc_addr(&self, mem: Instruction) -> usize {
        // check if we're addressing relative to ip
        // with PIC the compiler is going to use ip relative memory acceses
        if mem.is_ip_rel_memory_operand() {
            // if that is so, let iced calculate the address for us
            mem.ip_rel_memory_address() as usize
        } else {
            // get the displacement first, since any memory acces will have one (even if it's 0)
            let mut addr = mem.memory_displacement64() as usize;
            // check if there is a memory indexing register like in
            // ```x86asm
            // call   QWORD PTR [r12+r14*8]
            // ```
            // if that is the case, then multiply the value stored in the register (r14 in the above)
            // with its scale (8 in the above case)
            // and add the resulting value to the displacement
            if let Some(index_reg) = reg_from_iced_reg(mem.memory_index()) {
                let scale = mem.memory_index_scale() as usize;
                addr = addr.wrapping_add(scale * self.get_reg::<usize, 8>(index_reg));
            }

            // check if we are indexing a segment register
            // if so, add it to the addres
            // example:
            // ```x86asm
            // mov    rbx,QWORD PTR fs:0x10
            // ```
            // here fs is the segment register
            if let Some(seg_reg) = seg_from_iced_seg(mem.segment_prefix()) {
                addr = addr.wrapping_add(self.get_seg(seg_reg) as usize);
            }

            // check if there is a base register indexing the memory
            // if that is the case, add the value stored in the register to the current address
            // example:
            // ```x86asm
            // call   QWORD PTR [r12+r14*8]
            // ```
            // here r12 is the base register
            if let Some(base_reg) = reg_from_iced_reg(mem.memory_base()) {
                // this can be wrapping, for example you can have
                // ```x86asm
                // cmp    QWORD PTR [rdi-0x8],0x0
                // ```
                // substracting some displacement (i.e. doing a wrapping add (I could be wrong here))
                addr = addr.wrapping_add(self.get_reg::<usize, 8>(base_reg));
            }
            addr
        }
    }

    #[cfg(debug_assertions)]
    #[inline]
    /// pretty print the whole register state
    pub fn trace(&self) {
        print!(
            "\x1b[1;92m  RIP:   \x1b[0m {:#x} -> ",
            self.get_reg::<u64, 8>(Register::RIP)
        );
        if let Ok(inst_buf) = self.memory.peek(
            Virtaddr(self.get_reg::<usize, 8>(Register::RIP)),
            16,
            Perm(0),
        ) {
            let decoder = Decoder::with_ip(64, inst_buf, self.get_reg(Register::RIP), 0);
            let mut formatter = NasmFormatter::new();
            let mut instr_str = String::new();
            for inst in decoder.into_iter() {
                if inst.is_invalid() {
                    // skip invalid instrucions
                    continue;
                }
                formatter.format(&inst, &mut instr_str);
                instr_str.push(';');
                instr_str.push(' ');
            }
            println!("\x1b[38;2;255;100;0m{}\x1b[0m", instr_str);
        }
        println!("  Flag:   OD  SZ   P C");
        println!("\x1b[1;92m  RFLAGS:\x1b[0m {:0>12b}", self.rflags);
        // pretty print the gprs
        for reg in (Register::RAX as u8)..=(Register::RSP as u8) {
            let reg = unsafe { core::mem::transmute::<u8, Register>(reg) };
            let mut val = self.get_reg::<u64, 8>(reg);
            print!("\x1b[1;32m  {:?}:\x1b[0m {:#x}", reg, val);
            let mut depth = 0;
            while let Ok(new_val) = self
                .memory
                .read_primitive(Virtaddr(usize::try_from(val).unwrap()))
            {
                val = new_val;
                print!("\x1b[0m -> \x1b[;96m{val:#x?}");
                depth += 1;
                if depth > 5 {
                    break;
                }
            }
            println!("\x1b[0m");
        }
        for reg in (Register::R8 as u8)..=(Register::R15 as u8) {
            let reg = unsafe { core::mem::transmute::<u8, Register>(reg) };
            let val = self.get_reg::<u64, 8>(reg);
            print!("\x1b[1;32m  {:06?}:\x1b[0m {:#x}", reg, val);
        }
        println!();
        println!("segment regs: {:#x?}", self.segment_registers);
    }
}

/// an error was encountered during execution
#[derive(Debug, Clone, Copy)]
pub enum ExecErr {
    /// memory acces error
    AccErr { error: AccessError, ip: u64 },
    /// exit was called
    Exit { code: u64, ip: u64 },
}

impl From<AccessError> for ExecErr {
    fn from(value: AccessError) -> Self {
        Self::AccErr {
            error: value,
            ip: unsafe { IP },
        }
    }
}

pub enum SegReg {
    Fs,
    Gs,
}
/// the flags are as outlined [here](https://en.wikipedia.org/wiki/FLAGS_register) <br\>
/// mask: `1 << 0` Carry flag <br\>
/// mask: `1 << 1` reserverd (should be 1) <br\>
/// mask: `1 << 2` Parity flag <br\>
/// mask: `1 << 3` Reserved <br\>
/// mask: `1 << 4` Auxilliary Carry flag <br\>
/// mask: `1 << 5` Reserved <br\>
/// mask: `1 << 6` Zero flag <br\>
/// mask: `1 << 7` Sign flag <br\>
/// mask: `1 << 8` Trap flag <br\>
/// mask: `1 << 9` Interrupt enable flag <\br>
/// mask: `1 << 10` direction flag <\br>
/// mask: `1 << 11` overflow flag <\br>
enum Flag {
    /// mask: `1 << 0` Carry flag
    CF = 1 << 0,
    /// mask: `1 << 2` Parity flag
    PF = 1 << 2,
    /// mask: `1 << 4` Auxilliary Carry flag
    AuxCF = 1 << 4,
    /// mask: `1 << 6` Zero flag
    ZF = 1 << 6,
    /// mask: `1 << 7` Sign flag
    SF = 1 << 7,
    // mask: `1 << 8` Trap flag
    //TF = 1 << 8,
    // mask: `1 << 9` Interrupt enable flag
    //IEF = 1 << 9,
    // mask: `1 << 10` direction flag
    //DF = 1 << 10,
    /// mask: `1 << 11` overflow flag
    OF = 1 << 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    /// the intruction pointer
    RIP,
    /// general purpose register
    RAX,
    /// general purpose register
    RBX,
    /// general purpose register
    RCX,
    /// general purpose register
    RDX,
    /// general purpose register
    /// frame pointer
    RBP,
    /// general purpose register
    RSI,
    /// general purpose register
    RDI,
    /// general purpose register
    /// stack pointer
    RSP,
    /// general purpose register
    R8,
    /// general purpose register
    R9,
    /// general purpose register
    R10,
    /// general purpose register
    R11,
    /// general purpose register
    R12,
    /// general purpose register
    R13,
    /// general purpose register
    R14,
    /// general purpose register
    R15,
    // Flag register <br\>
    // the flags are as outlined [here](https://en.wikipedia.org/wiki/FLAGS_register/) <br\>
    // mask: `1 << 0` Carry flag <br\>
    // mask: `1 << 1` reserverd (should be 1) <br\>
    // mask: `1 << 2` Parity flag <br\>
    // mask: `1 << 3` Reserved <br\>
    // mask: `1 << 4` Auxilliary Carry flag <br\>
    // mask: `1 << 5` Reserved <br\>
    // mask: `1 << 6` Zero flag <br\>
    // mask: `1 << 7` Sign flag <br\>
    // mask: `1 << 8` Trap flag <br\>
    // mask: `1 << 9` Interrupt enable flagi <\br>
    // mask: `1 << 10` direction flag <\br>
    // mask: `1 << 11` overflow flag <\br>
    // RFLAGS,
    // SIMD registers
    /// SIMD register, 128 bit
    Xmm0,
    /// SIMD register, 128 bit
    Xmm1,
    /// SIMD register, 128 bit
    Xmm2,
    /// SIMD register, 128 bit
    Xmm3,
    /// SIMD register, 128 bit
    Xmm4,
    /// SIMD register, 128 bit
    Xmm5,
    /// SIMD register, 128 bit
    Xmm6,
    /// SIMD register, 128 bit
    Xmm7,
    /// SIMD register, 128 bit
    Xmm8,
    /// SIMD register, 128 bit
    Xmm9,
    /// SIMD register, 128 bit
    Xmm10,
    /// SIMD register, 128 bit
    Xmm11,
    /// SIMD register, 128 bit
    Xmm12,
    /// SIMD register, 128 bit
    Xmm13,
    /// SIMD register, 128 bit
    Xmm14,
    /// SIMD register, 128 bit
    Xmm15,
    /// general purpose register
    /// 16 bit high byte of `EAX`
    AH,
    /// general purpose register
    /// 16 bit high byte of `EBX`
    BH,
    /// general purpose register
    /// 16 bit high byte of `ECX`
    CH,
    /// general purpose register
    /// 16 bit high byte of `EDX`
    DH,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Bitness {
    Eight = 8,
    Sixteen = 16,
    ThirtyTwo = 32,
    SixtyFour = 64,
    HundredTwentyEigth = 128,
}
#[inline]
fn reg_from_iced_reg(reg: iced_x86::Register) -> Option<Register> {
    use self::Register::*;
    use iced_x86::Register;
    match reg {
        Register::None => None,
        Register::RAX => Some(RAX),
        Register::EAX => Some(RAX),
        Register::AX => Some(RAX),
        Register::AL => Some(RAX),
        Register::RCX => Some(RCX),
        Register::ECX => Some(RCX),
        Register::CX => Some(RCX),
        Register::CL => Some(RCX),
        Register::CH => Some(CH),
        Register::RDX => Some(RDX),
        Register::EDX => Some(RDX),
        Register::DX => Some(RDX),
        Register::DL => Some(RDX),
        Register::DH => Some(DH),
        Register::RBX => Some(RBX),
        Register::EBX => Some(RBX),
        Register::BL => Some(RBX),
        Register::RSP => Some(RSP),
        Register::RBP => Some(RBP),
        Register::EBP => Some(RBP),
        Register::BH => Some(BH),
        Register::RSI => Some(RSI),
        Register::ESI => Some(RSI),
        Register::SIL => Some(RSI),
        Register::RDI => Some(RDI),
        Register::EDI => Some(RDI),
        Register::DIL => Some(RDI),
        Register::R8 => Some(R8),
        Register::R8D => Some(R8),
        Register::R9 => Some(R9),
        Register::R9D => Some(R9),
        Register::R10 => Some(R10),
        Register::R10D => Some(R10),
        Register::R10L => Some(R10),
        Register::R11 => Some(R11),
        Register::R11D => Some(R11),
        Register::R11L => Some(R11),
        Register::R12 => Some(R12),
        Register::R12D => Some(R12),
        Register::R12L => Some(R12),
        Register::R13 => Some(R13),
        Register::R13D => Some(R13),
        Register::R14 => Some(R14),
        Register::R14L => Some(R14),
        Register::R14D => Some(R14),
        Register::R15 => Some(R15),
        Register::R15D => Some(R15),
        Register::R15L => Some(R15),
        Register::EIP => Some(RIP),
        Register::RIP => Some(RIP),
        Register::XMM0 => Some(Xmm0),
        Register::XMM1 => Some(Xmm1),
        Register::XMM2 => Some(Xmm2),
        Register::XMM3 => Some(Xmm3),
        Register::XMM4 => Some(Xmm4),
        Register::XMM5 => Some(Xmm5),
        Register::XMM6 => Some(Xmm6),
        x => todo!("implement register {x:?}"),
    }
}

fn seg_from_iced_seg(reg: iced_x86::Register) -> Option<SegReg> {
    match reg {
        iced_x86::Register::FS => Some(SegReg::Fs),
        iced_x86::Register::SS | iced_x86::Register::None | iced_x86::Register::DS => None,
        x => todo!("{x:?} at {:#x}", unsafe { IP }),
    }
}

#[inline]
fn bitness(instr: Instruction, op: u32) -> Bitness {
    match instr.op_kind(op) {
        OpKind::Register => reg_bitness(instr.op_register(op)),
        OpKind::NearBranch16 => Bitness::Sixteen,
        OpKind::NearBranch32 => Bitness::ThirtyTwo,
        OpKind::NearBranch64 => Bitness::SixtyFour,
        OpKind::FarBranch16 => Bitness::Sixteen,
        OpKind::FarBranch32 => Bitness::ThirtyTwo,
        OpKind::Immediate8 => Bitness::Eight,
        OpKind::Immediate8to16 | OpKind::Immediate16 => Bitness::Sixteen,
        OpKind::Immediate8to32 | OpKind::Immediate32 => Bitness::ThirtyTwo,
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => {
            Bitness::SixtyFour
        }
        OpKind::Memory => match instr.memory_size() {
            iced_x86::MemorySize::UInt8 | iced_x86::MemorySize::Int8 => Bitness::Eight,
            iced_x86::MemorySize::UInt16 | iced_x86::MemorySize::Int16 => Bitness::Sixteen,
            iced_x86::MemorySize::UInt32 | iced_x86::MemorySize::Int32 => Bitness::ThirtyTwo,
            iced_x86::MemorySize::UInt64 | iced_x86::MemorySize::Int64 => Bitness::SixtyFour,
            iced_x86::MemorySize::UInt128 | iced_x86::MemorySize::Int128 => {
                Bitness::HundredTwentyEigth
            }
            x => todo!("{x:?}"),
        },
        x => todo!("{x:?}"),
    }
}

fn reg_bitness(reg: iced_x86::Register) -> Bitness {
    match reg {
        // https://stackoverflow.com/questions/1753602/what-are-the-names-of-the-new-x86-64-processors-registers
        iced_x86::Register::AL
        | iced_x86::Register::R11L
        | iced_x86::Register::R14L
        | iced_x86::Register::R15L
        | iced_x86::Register::CL
        | iced_x86::Register::DL
        | iced_x86::Register::BL
        | iced_x86::Register::AH
        | iced_x86::Register::CH
        | iced_x86::Register::DH
        | iced_x86::Register::BH
        | iced_x86::Register::SPL
        | iced_x86::Register::BPL
        | iced_x86::Register::SIL
        | iced_x86::Register::DIL
        | iced_x86::Register::R10L => Bitness::Eight,
        iced_x86::Register::AX
        | iced_x86::Register::CX
        | iced_x86::Register::DX
        | iced_x86::Register::BX
        | iced_x86::Register::SP
        | iced_x86::Register::BP
        | iced_x86::Register::SI
        | iced_x86::Register::DI => Bitness::Sixteen,
        iced_x86::Register::EBP
        | iced_x86::Register::EAX
        | iced_x86::Register::EBX
        | iced_x86::Register::ECX
        | iced_x86::Register::EDX
        | iced_x86::Register::EDI
        | iced_x86::Register::ESI
        | iced_x86::Register::R8D
        | iced_x86::Register::R9D
        | iced_x86::Register::R10D
        | iced_x86::Register::R11D
        | iced_x86::Register::R12D
        | iced_x86::Register::R13D
        | iced_x86::Register::R14D
        | iced_x86::Register::R15D => Bitness::ThirtyTwo,
        iced_x86::Register::RAX
        | iced_x86::Register::RCX
        | iced_x86::Register::RDX
        | iced_x86::Register::RBX
        | iced_x86::Register::RSP
        | iced_x86::Register::RBP
        | iced_x86::Register::RSI
        | iced_x86::Register::RDI
        | iced_x86::Register::R8
        | iced_x86::Register::R9
        | iced_x86::Register::R10
        | iced_x86::Register::R11
        | iced_x86::Register::R12
        | iced_x86::Register::R13
        | iced_x86::Register::R14
        | iced_x86::Register::R15
        | iced_x86::Register::RIP => Bitness::SixtyFour,
        iced_x86::Register::XMM0
        | iced_x86::Register::XMM1
        | iced_x86::Register::XMM2
        | iced_x86::Register::XMM3
        | iced_x86::Register::XMM4
        | iced_x86::Register::XMM5 => Bitness::HundredTwentyEigth,

        x => todo!("{x:?}"),
    }
}
