use core::fmt::Debug;
use std::{hint::unreachable_unchecked, path::Path};

// this is impossible to because of https://github.com/bitdefender/bddisasm/issues/82 ;(
// use bddisasm::{operand::Operands, DecodedInstruction, OpInfo, Operand};
use iced_x86::{Decoder, Formatter, Instruction, Mnemonic, NasmFormatter, OpKind};

#[cfg(debug_assertions)]
use crate::mmu::PERM_EXEC;
use crate::{
    mmu::{Virtaddr, MMU},
    primitive::Primitive,
};
#[cfg(debug_assertions)]
use std::{io::Write, ops::Range};

pub struct Emu {
    memory: MMU,
    registers: [u64; 18],
    simd_registers: [u128; 16],
    #[cfg(debug_assertions)]
    pub stack_depth: usize,
    #[cfg(debug_assertions)]
    exec_range: Range<usize>,
}

impl Emu {
    pub fn load<P: AsRef<Path>>(&mut self, file: P) {
        let (rip, frame, exec_range) = self.memory.load(file);
        self.set_reg(rip.0 as u64, Register::RIP);
        self.set_reg(frame.0 as u64, Register::RSP);
        // self.set_reg(frame.0 as u64 - 8, Register::RBP);

        #[cfg(debug_assertions)]
        {
            self.exec_range = exec_range;
        }

        // Set up the program name
        let argv = self
            .memory
            .allocate(8)
            .expect("Failed to allocate program name");
        self.memory
            .write_from(Virtaddr(argv.0 - 8), b"test\0")
            .expect("Failed to write program name");

        macro_rules! push {
            ($expr:expr) => {
                let sp = self.get_reg::<u64, 8>(Register::RSP) as usize
                    - core::mem::size_of_val(&$expr) as usize;
                self.memory
                    .write_primitive(Virtaddr(sp), $expr)
                    .expect("Push failed");
                self.set_reg(sp, Register::RSP);
            };
        }

        // Set up the initial program stack state
        push!(0u64); // Auxp
        push!(0u64); // Envp
        push!(0u64); // Argv end
        push!(argv.0); // Argv
        push!(1u64); // Argc
    }

    pub fn new(size: usize) -> Self {
        Self {
            memory: MMU::new(size),
            registers: [0; 18],
            simd_registers: [0; 16],
            #[cfg(debug_assertions)]
            stack_depth: 0,
            #[cfg(debug_assertions)]
            exec_range: Range { start: 0, end: 0 },
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
        if register == Register::RSP {
            if self.registers[Register::RSP as usize] != 0 {
                self.stack_depth = (self.stack_depth as isize
                    + self.registers[Register::RSP as usize] as isize
                    - (val.to_u64() as isize)) as usize;
            }
        }
        if (register as u8) < self.registers.len() as u8 {
            self.registers[register as usize] = val.to_u64();
        } else if (register as u8) < (Register::AH as u8) {
            // we're a 128 bit register
            self.simd_registers[register as usize - self.registers.len()] = val.try_into().unwrap();
        } else {
            // we're the high part of an register
            // so first mask off the unused bits
            self.registers[register as usize - 32] &= !0xff_00;
            // then set it to it's new value
            self.registers[register as usize - 32] |=
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
            T::try_from(((self.registers[register as usize - 32] as u16) & 0xff_00) >> 8).unwrap()
        }
    }

    #[inline]
    pub fn get_val<T: Primitive<BYTES>, const BYTES: usize>(
        &self,
        instruction: Instruction,
        index: u32,
    ) -> Result<T, ()>
    where
        <T as TryFrom<u16>>::Error: Debug,
        <T as TryFrom<u32>>::Error: Debug,
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
    {
        let operand = instruction.op_kind(index);
        match operand {
            OpKind::Register => {
                let reg: Register = reg_from_op_reg(instruction.op_register(index)).unwrap();
                Ok(self.get_reg(reg))
            }
            OpKind::NearBranch64 => Ok(instruction.near_branch64().try_into().unwrap()),
            OpKind::Immediate8 => T::try_from(instruction.immediate8()).map_err(|_| ()),
            OpKind::Immediate16 => T::try_from(instruction.immediate16()).map_err(|_| ()),
            OpKind::Immediate32 => T::try_from(instruction.immediate32()).map_err(|_| ()),
            OpKind::Immediate64 => T::try_from(instruction.immediate64()).map_err(|_| ()),
            OpKind::Immediate8to16 => {
                T::try_from(instruction.immediate8to16() as u16).map_err(|_| ())
            }
            OpKind::Immediate8to32 => {
                T::try_from(instruction.immediate8to32() as u32).map_err(|_| ())
            }
            OpKind::Immediate8to64 => {
                T::try_from(instruction.immediate8to64() as u64).map_err(|_| ())
            }
            OpKind::Immediate32to64 => {
                T::try_from(instruction.immediate32to64() as u64).map_err(|_| ())
            }
            OpKind::Memory => {
                let address: usize = self.calc_addr(instruction);
                self.memory
                    .read_primitive(Virtaddr(address))
                    .map(T::from_ne_bytes)
            }
            x => todo!("{x:?}"),
        }
    }

    #[cfg(debug_assertions)]
    /// pretty print the stack, looking `length` `T`'s down from RSP
    pub fn print_stack<T: Primitive<BYTES>, const BYTES: usize>(&self, length: usize) -> ()
    where
        usize: TryFrom<T>,
        <usize as TryFrom<T>>::Error: Debug,
        T: TryFrom<usize>,
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
                .read_primitive::<BYTES>(Virtaddr(usize::try_from(val).unwrap()))
            {
                val = T::from_ne_bytes(new_val);
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
                    depth += 1;
                    if depth > 5 {
                        break 'recursive_memory_lookup;
                    }
                }
                print!("\x1b[;96m{val:#x?}\x1b[0m");
            }
            println!("\x1b[0m");
        }
    }

    pub fn run_emu(&mut self) -> Result<(), ()> {
        #[cfg(debug_assertions)]
        let mut call_depth = 0;
        'next_instr: loop {
            // we have to look ahead 16 bytes into memory since that's the maximum size of x86 instructions

            #[cfg(debug_assertions)]
            if false {
                // cls
                print!("\x1b[2J\x1b[1;1H");
                self.trace();
                self.print_stack::<u64, 8>((self.stack_depth - 3 * 8).min(30 * 8));
                print!("\x1b[;96mcontinue?: \x1b[0m");
                if false {
                    let _ = std::io::stdout().flush();
                    let mut str = String::new();
                    let _ = std::io::stdin().read_line(&mut str);
                }
                println!();
            }

            // so we allocate a buffer for those on the stack here
            let mut inst_buf = [0u8; 16];
            // and read them from the current instruction pointer
            self.memory.read_to(
                // we currently only support running this on x86 hosts
                // so it is fine to assume that a usize has size 8 bytes here
                Virtaddr(self.get_reg::<usize, 8>(Register::RIP)),
                &mut inst_buf,
            )?;

            // TODO: support 32 bit mode
            let instruction =
                Decoder::with_ip(64, &inst_buf, self.get_reg(Register::RIP), 0).decode();

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
            macro_rules! push {
                ($expr:expr) => {
                    let sp = self.get_reg::<u64, 8>(Register::RSP) as usize
                        - core::mem::size_of_val(&$expr) as usize;
                    self.memory.write_primitive(Virtaddr(sp), $expr)?;
                    self.set_reg(sp, Register::RSP);
                };
            }
            macro_rules! pop {
                ($exp:expr) => {{
                    let sp = self.get_reg::<u64, 8>(Register::RSP) as usize;
                    self.set_reg(sp + $exp as usize, Register::RSP);
                    self.memory.read_primitive(Virtaddr(sp))?
                }};
            }
            macro_rules! match_bitness_ts {
                ($id:ident) => {
                    match bitness(instruction) {
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
                    match bitness(instruction) {
                        Bitness::Eight => $id!(u8),
                        Bitness::Sixteen => $id!(u16),
                        Bitness::ThirtyTwo => $id!(u32),
                        Bitness::SixtyFour => $id!(u64),
                        Bitness::HundredTwentyEigth => $id!(u128),
                    }
                };
            }

            macro_rules! jmp {
                () => {
                    // get the new ip
                    let new_ip: u64 = self.get_val::<u64, 8>(instruction, 0)?;
                    self.set_reg(new_ip, Register::RIP);
                    // and jump to it
                    continue 'next_instr;
                };
            }

            // set the instruction pointer to the next instruction
            inc_reg!(instruction.len(), Register::RIP);
            // TODO: get rid of boilerplate code
            match instruction.mnemonic() {
                /*
                        +-------------------------+
                        | Arithmetic Instructions |
                        +-------------------------+
                */
                Mnemonic::Add => {
                    // add, as documented by https://www.felixcloutier.com/x86/add
                    let mut overflowing = false;
                    macro_rules! sized_add {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, |x, y| {
                                let a = x.overflowing_add(y);
                                overflowing = a.1;
                                a.0
                            })?
                        };
                    }
                    self.set_reg::<u8, 1>(
                        overflowing as u8 | self.get_reg::<u8, 1>(Register::RFLAGS),
                        Register::RFLAGS,
                    );

                    match_bitness_ts!(sized_add);
                }
                Mnemonic::Sub => {
                    // sub, as documented by https://www.felixcloutier.com/x86/sub
                    let mut overflowing = false;
                    macro_rules! sized_sub {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, |x, y| {
                                let a = x.overflowing_sub(y);
                                overflowing = a.1;
                                a.0
                            })?
                        };
                    }

                    self.set_reg::<u8, 1>(
                        overflowing as u8 | self.get_reg::<u8, 1>(Register::RFLAGS),
                        Register::RFLAGS,
                    );

                    match_bitness_ts!(sized_sub)
                }
                Mnemonic::Sbb => {
                    // TODO: change this to use borrowed sub
                    let cf = self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 0);
                    macro_rules! sized_sbb {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, |x, y| {
                                x - (y.wrapping_add(cf as $typ))
                            })?
                        };
                    }

                    match_bitness_ts!(sized_sbb)
                }
                Mnemonic::Shr => {
                    // shr, as documented by https://www.felixcloutier.com/x86/sal:sar:shl:shr
                    macro_rules! sized_shr {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, core::ops::Shr::shr)?
                        };
                    }

                    match_bitness_ts!(sized_shr)
                }
                Mnemonic::Sar => {
                    // sar, as documented by https://www.felixcloutier.com/x86/sal:sar:shl:shr
                    // as by https://www.reddit.com/r/rust/comments/2lp3il/where_is_arithmetic_signed_rightshift,
                    // we simply have to change our type to signed herewe simply have to change our type to signed here
                    macro_rules! sized_shr {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, core::ops::Shr::shr)?
                        };
                    }
                    match bitness(instruction) {
                        Bitness::Eight => sized_shr!(i8, 1),
                        Bitness::Sixteen => sized_shr!(i16, 2),
                        Bitness::ThirtyTwo => sized_shr!(i32, 4),
                        Bitness::SixtyFour => sized_shr!(i64, 8),
                        Bitness::HundredTwentyEigth => sized_shr!(i128, 16),
                    }
                }
                Mnemonic::Shl => {
                    // shl, as documented by https://www.felixcloutier.com/x86/sal:sar:shl:shr
                    macro_rules! sized_shr {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, core::ops::Shl::shl)?
                        };
                    }

                    match_bitness_ts!(sized_shr)
                }
                Mnemonic::Imul => {
                    let cf = match self.get_val::<u64, 8>(instruction, 2) {
                        Ok(cf) => cf,
                        Err(_) => 1,
                    };
                    macro_rules! sized_imul {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, |x, y| {
                                x.wrapping_mul(y.wrapping_mul(cf as $typ))
                            })?
                        };
                    }

                    match_bitness_ts!(sized_imul);
                }
                Mnemonic::Idiv => {
                    // TODO: handle 8 bit case
                    macro_rules! sized_imul {
                        ($typ:ty,$size:literal,$double_typ:ty) => {{
                            let lhs: $double_typ = ((self.get_reg::<$typ, $size>(Register::RDX)
                                as $double_typ)
                                << ($size * 8))
                                | (self.get_reg::<$typ, $size>(Register::RAX) as $double_typ);
                            let rhs: $double_typ =
                                self.get_val::<$typ, $size>(instruction, 0)? as $double_typ;
                            self.set_reg::<$typ, $size>((lhs / rhs) as $typ, Register::RAX);
                            self.set_reg::<$typ, $size>((lhs % rhs) as $typ, Register::RDX);
                        }};
                    }
                    match bitness(instruction) {
                        Bitness::Eight => todo!(),
                        Bitness::Sixteen => sized_imul!(u16, 2, i32),
                        Bitness::ThirtyTwo => sized_imul!(u32, 4, i64),
                        Bitness::SixtyFour => sized_imul!(u64, 8, i128),
                        Bitness::HundredTwentyEigth => unsafe { unreachable_unchecked() },
                    }
                }
                Mnemonic::Div => {
                    // div, as documented by https://www.felixcloutier.com/x86/div
                    // TODO: handle 8 bit case
                    macro_rules! sized_imul {
                        ($typ:ty,$size:literal,$double_typ:ty) => {{
                            let lhs: $double_typ = ((self.get_reg::<$typ, $size>(Register::RDX)
                                as $double_typ)
                                << ($size * 8))
                                | (self.get_reg::<$typ, $size>(Register::RAX) as $double_typ);
                            let rhs: $double_typ =
                                self.get_val::<$typ, $size>(instruction, 0)? as $double_typ;
                            self.set_reg::<$typ, $size>((lhs / rhs) as $typ, Register::RAX);
                            self.set_reg::<$typ, $size>((lhs % rhs) as $typ, Register::RDX);
                        }};
                    }
                    match bitness(instruction) {
                        Bitness::Eight => todo!(),
                        Bitness::Sixteen => sized_imul!(u16, 2, u32),
                        Bitness::ThirtyTwo => sized_imul!(u32, 4, u64),
                        Bitness::SixtyFour => sized_imul!(u64, 8, u128),
                        Bitness::HundredTwentyEigth => unsafe { unreachable_unchecked() },
                    }
                }

                /*
                        +----------------------+
                        | Logical Instructions |
                        +----------------------+
                */
                Mnemonic::And | Mnemonic::Pand => {
                    // as documented by https://www.felixcloutier.com/x86/and
                    macro_rules! sized_and {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(
                                instruction,
                                core::ops::BitAnd::bitand,
                            )?
                        };
                    }

                    match_bitness_ts!(sized_and)
                }
                Mnemonic::Xor => {
                    // xor, as documented by https://www.felixcloutier.com/x86/xor
                    macro_rules! sized_xor {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(
                                instruction,
                                core::ops::BitXor::bitxor,
                            )?
                        };
                    }

                    match_bitness_ts!(sized_xor)
                }
                Mnemonic::Not => {
                    macro_rules! sized_not {
                        ($typ:ty,$size:literal) => {{
                            let val: $typ = self.get_val(instruction, 0)?;
                            self.set_val::<$typ, $size>(instruction, 0, !val)?;
                        }};
                    }

                    match_bitness_ts!(sized_not)
                }
                Mnemonic::Neg => {
                    macro_rules! sized_neg {
                        ($typ:ty,$size:literal) => {{
                            let val: $typ = self.get_val(instruction, 0)?;
                            self.set_val::<$typ, $size>(instruction, 0, -val)?;
                        }};
                    }

                    match bitness(instruction) {
                        Bitness::Eight => sized_neg!(i8, 1),
                        Bitness::Sixteen => sized_neg!(i16, 2),
                        Bitness::ThirtyTwo => sized_neg!(i32, 4),
                        Bitness::SixtyFour => sized_neg!(i64, 8),
                        Bitness::HundredTwentyEigth => sized_neg!(i128, 16),
                    }
                }
                Mnemonic::Or => {
                    // or, as documented by https://www.felixcloutier.com/x86/or
                    macro_rules! sized_or {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, core::ops::BitOr::bitor)?
                        };
                    }

                    match_bitness_ts!(sized_or)
                }
                Mnemonic::Cqo => {
                    let val = self.get_reg::<u64, 8>(Register::RAX) as i128 as u128;
                    self.set_reg(val as u64, Register::RAX);
                    self.set_reg((val >> 64) as u64, Register::RDX);
                }
                Mnemonic::Cdqe => {
                    let val = self.get_reg::<u32, 4>(Register::RAX) as i64 as u64;
                    self.set_reg(val as u32, Register::RAX);
                    self.set_reg((val >> 32) as u32, Register::RDX);
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
                    push!(self.get_reg::<usize, 8>(Register::RIP));
                    // set rip to the new ip and continue execution there
                    self.set_reg(new_ip, Register::RIP);
                    continue 'next_instr;
                }
                Mnemonic::Ret => {
                    // get the new ip
                    let new_ip: u64 = u64::from_ne_bytes(pop!(8));
                    #[cfg(debug_assertions)]
                    {
                        // println!("{:\t<1$}ret to: {new_ip:#x}", "", call_depth);
                        println!(
                            "{:\t<1$}⮡ {rax:#x}",
                            "",
                            call_depth,
                            rax = self.get_reg::<usize, 8>(Register::RAX)
                        );
                        call_depth -= 1;
                    }
                    self.set_reg(new_ip, Register::RIP);
                    continue 'next_instr;
                }

                // | jump instructions |
                Mnemonic::Jne => {
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 6) == 0 {
                        println!("jumping to {:#x}", self.get_val::<u64, 8>(instruction, 0)?);
                        jmp!();
                    }
                    println!(
                        "not jumping to {:#x}",
                        self.get_val::<u64, 8>(instruction, 0)?
                    );
                }
                Mnemonic::Jbe => {
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 6) != 0
                        || self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 0) != 0
                    {
                        jmp!();
                    }
                }
                Mnemonic::Je => {
                    if self.get_reg::<u64, 8>(Register::RFLAGS) & (1 << 6) != 0 {
                        jmp!();
                    }
                }
                Mnemonic::Jb => {
                    if self.get_reg::<u64, 8>(Register::RFLAGS) & (1 << 0) != 0 {
                        jmp!();
                    }
                }
                Mnemonic::Jle => {
                    // if the ZF==1
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 6) != 0
                        // or SF!=OF
                        || (self.get_reg::<u16, 2>(Register::RFLAGS) & (1 << 11)).count_ones()
                            != (self.get_reg::<u16, 2>(Register::RFLAGS) & (1 << 7)).count_ones()
                    {
                        jmp!();
                    }
                }
                Mnemonic::Jg => {
                    // if ZF==0
                    if self.get_reg::<u64, 8>(Register::RFLAGS) & (1 << 6) == 0
                        // and SF==OF
                        && (self.get_reg::<u16, 2>(Register::RFLAGS) & (1 << 11)).count_ones()
                            == (self.get_reg::<u16, 2>(Register::RFLAGS) & (1 << 7)).count_ones()
                    {
                        jmp!();
                    }
                }
                Mnemonic::Ja => {
                    // if ZF==0
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 6) == 0
                        // and CF==0
                        && self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 0) == 0
                    {
                        jmp!();
                    }
                }
                Mnemonic::Jae => {
                    // if CF==0
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 0) == 0 {
                        jmp!();
                    }
                }
                Mnemonic::Js => {
                    // if CF==0
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 7) != 0 {
                        jmp!();
                    }
                }
                Mnemonic::Jmp => {
                    jmp!();
                }

                // | FLAGS setting instructions |
                Mnemonic::Cmp => {
                    // TODO: make this macro more generic, so
                    // we can use it in other contexts as well

                    // This is the cmp instruction as documented by https://www.felixcloutier.com/x86/cmp
                    // note that https://www.felixcloutier.com/x86/jcc is more helpful for finding out when
                    // to set which flag
                    macro_rules! cmp_with_type {
                        ($typ:ty) => {{
                            let lhs: $typ = self.get_val(instruction, 0)?;
                            let rhs: $typ = self.get_val(instruction, 1)?;
                            // XXX: actually make this correct
                            match lhs.cmp(&rhs) {
                                // unset the carry flag and the zero flag if above
                                core::cmp::Ordering::Greater => self.set_reg(
                                    /* !*/
                                    (0 << 6) | (0 << 0), /*& self.get_reg::<u64, 8>(Register::RFLAGS)*/
                                    Register::RFLAGS,
                                ),
                                // set the zero flag if eq
                                core::cmp::Ordering::Equal => self.set_reg(1 << 6, Register::RFLAGS),
                                // unset the carry flag and set the zero flag if less
                                core::cmp::Ordering::Less => self.set_reg(
                                    (0 << 6) | (1 << 0), /*& self.get_reg::<u64, 8>(Register::RFLAGS)*/
                                    Register::RFLAGS,
                                ),
                            }
                        }};
                    }

                    match_bitness_typ!(cmp_with_type)
                }
                Mnemonic::Test => {
                    let lhs: usize = self.get_val(instruction, 0)?;
                    let rhs: usize = self.get_val(instruction, 1)?;
                    let and_res: usize = lhs & rhs;
                    self.set_reg(
                        // TODO: handle parity flag
                        ((and_res & (1 << 63)) >> 56) | if and_res == 0 { 1 << 6 } else { 0 << 6 },
                        Register::RFLAGS,
                    );
                }

                /*
                        +----------------------+
                        | *mov*   Instructions |
                        +----------------------+
                */
                Mnemonic::Cmovne => {
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 6) == 0 {
                        // this is some hacky shit, I love it
                        macro_rules! sized_mov {
                            ($typ:ty,$size:literal) => {
                                self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                            };
                        }

                        match_bitness_ts!(sized_mov)
                    }
                }
                Mnemonic::Cmove => {
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 6) != 0 {
                        // this is some hacky shit, I love it
                        macro_rules! sized_mov {
                            ($typ:ty,$size:literal) => {
                                self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                            };
                        }

                        match_bitness_ts!(sized_mov)
                    }
                }
                Mnemonic::Cmova => {
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 6) == 0
                        // and CF==0
                        && self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 0) == 0
                    {
                        // this is some hacky shit, I love it
                        macro_rules! sized_mov {
                            ($typ:ty,$size:literal) => {
                                self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                            };
                        }

                        match_bitness_ts!(sized_mov)
                    }
                }
                Mnemonic::Cmovae => {
                    if self.get_reg::<u8, 1>(Register::RFLAGS) & (1 << 0) == 0 {
                        // this is some hacky shit, I love it
                        macro_rules! sized_mov {
                            ($typ:ty,$size:literal) => {
                                self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                            };
                        }

                        match_bitness_ts!(sized_mov)
                    }
                }
                Mnemonic::Cmovg => {
                    if self.get_reg::<u64, 8>(Register::RFLAGS) & (1 << 6) == 0
                        // and SF==OF
                        && (self.get_reg::<u16, 2>(Register::RFLAGS) & (1 << 11)).count_ones()
                            == (self.get_reg::<u16, 2>(Register::RFLAGS) & (1 << 7)).count_ones()
                    {
                        // this is some hacky shit, I love it
                        macro_rules! sized_mov {
                            ($typ:ty,$size:literal) => {
                                self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                            };
                        }

                        match_bitness_ts!(sized_mov)
                    }
                }
                Mnemonic::Cmovb => {
                    if self.get_reg::<u64, 8>(Register::RFLAGS) & (1 << 0) != 0 {
                        // this is some hacky shit, I love it
                        macro_rules! sized_mov {
                            ($typ:ty,$size:literal) => {
                                self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                            };
                        }

                        match_bitness_ts!(sized_mov)
                    }
                }
                Mnemonic::Mov => {
                    // mov, as documented by https://www.felixcloutier.com/x86/mov
                    // this is some hacky shit
                    macro_rules! sized_mov {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                        };
                    }

                    match_bitness_ts!(sized_mov)
                }
                Mnemonic::Movd => {
                    // this is some hacky shit, I love it
                    self.do_loar_op::<u32, _, 4>(instruction, |_, x| x)?;
                }
                Mnemonic::Movq => {
                    let val: u64 = self.get_val(instruction, 1)?;
                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Movsxd => {
                    // movsxd, as documented by https://www.felixcloutier.com/x86/movsx:movsxd
                    // this is some hacky shit, I love it
                    // let's hope that this sign extends
                    macro_rules! sized_mov {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                        };
                    }
                    match bitness(instruction) {
                        Bitness::Eight => sized_mov!(i8, 1),
                        Bitness::Sixteen => sized_mov!(i16, 2),
                        Bitness::ThirtyTwo => sized_mov!(i32, 4),
                        Bitness::SixtyFour => sized_mov!(i64, 8),
                        Bitness::HundredTwentyEigth => sized_mov!(i128, 16),
                    }
                }
                Mnemonic::Movzx => {
                    // this is some hacky shit, I love it
                    macro_rules! sized_mov {
                        ($typ:ty,$size:literal) => {
                            self.do_loar_op::<$typ, _, $size>(instruction, |_, x| x)?
                        };
                    }

                    match_bitness_ts!(sized_mov)
                }
                /*
                        +----------------------+
                        | Stack   Instructions |
                        +----------------------+
                */
                Mnemonic::Pop => {
                    macro_rules! pop_sized {
                        ($typ:ty, $size:literal) => {{
                            let val = <$typ>::from_ne_bytes(pop!($size));
                            self.set_val(instruction, 0, val)?;
                        }};
                    }
                    match_bitness_ts!(pop_sized)
                }
                Mnemonic::Push => {
                    macro_rules! push_sized {
                        ($typ:ty) => {{
                            let val: $typ = self.get_val(instruction, 0)?;
                            push!(val);
                        }};
                    }

                    match_bitness_typ!(push_sized)
                }
                /*
                        +-----------------------------+
                        | Miscellaneous  Instructions |
                        +-----------------------------+
                */
                Mnemonic::Cpuid => {
                    // pretend we're and old intel cpu
                    // https://de.wikipedia.org/wiki/CPUID
                    let ax = self.get_reg::<u8, 1>(Register::RAX);
                    if ax == 0 {
                        unsafe {
                            self.set_reg(
                                std::mem::transmute::<[u8; 4], u32>(*b"letn") as u32,
                                Register::RBX,
                            );
                        }
                        unsafe {
                            self.set_reg(
                                std::mem::transmute::<[u8; 4], u32>(*b"Ieni") as u32,
                                Register::RDX,
                            );
                        }
                        unsafe {
                            self.set_reg(
                                std::mem::transmute::<[u8; 4], u32>(*b"uneG") as u32,
                                Register::RCX,
                            );
                        }
                    } else {
                        // since it's easy to find, let's pretend we're a celeron m
                        self.set_reg(0x06EC, Register::RCX);
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
                                .write_primitive(Virtaddr(index + base_addr), rax_val)?;
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
                    macro_rules! sized_sete {
                        ($typ:ty,$size:literal) => {{
                            if self.get_reg::<$typ, $size>(Register::RFLAGS) & (1 << 6) != 0 {
                                self.set_val::<$typ, $size>(instruction, 0, 1)?;
                            } else {
                                self.set_val::<$typ, $size>(instruction, 0, 0)?;
                            }
                        }};
                    }
                    match_bitness_ts!(sized_sete)
                }
                Mnemonic::Setne => {
                    macro_rules! sized_sete {
                        ($typ:ty,$size:literal) => {{
                            if self.get_reg::<$typ, $size>(Register::RFLAGS) & (1 << 6) == 0 {
                                self.set_val::<$typ, $size>(instruction, 0, 1)?;
                            } else {
                                self.set_val::<$typ, $size>(instruction, 0, 0)?;
                            }
                        }};
                    }
                    match_bitness_ts!(sized_sete)
                }
                /*
                        +----------------------+
                        | SIMD    Instructions |
                        +----------------------+
                */
                Mnemonic::Punpckldq => {
                    let lhs: core::simd::Simd<u32, 2> =
                        core::simd::Simd::<u32, 2>::from_array(unsafe {
                            core::mem::transmute::<u64, [u32; 2]>(
                                self.get_val::<u64, 8>(instruction, 0)?,
                            )
                        });
                    let rhs: core::simd::Simd<u32, 2> =
                        core::simd::Simd::<u32, 2>::from_array(unsafe {
                            core::mem::transmute::<u64, [u32; 2]>(
                                self.get_val::<u64, 8>(instruction, 1)?,
                            )
                        });
                    let inter = lhs.interleave(rhs);
                    let mut buf = [0u32; 4];
                    inter.0.copy_to_slice(&mut buf[..2]);
                    inter.1.copy_to_slice(&mut buf[2..4]);
                    let new_val = unsafe { core::mem::transmute::<[u32; 4], u128>(buf) };
                    self.set_reg(new_val, Register::Xmm1);
                }
                Mnemonic::Punpcklqdq => {
                    self.do_loar_op::<u128, _, 16>(instruction, |x, y| {
                        (x & (u64::MAX as u128)) | ((y & (u64::MAX as u128)) << 64)
                    })?;
                }
                Mnemonic::Movhps => match instruction.op0_kind() {
                    OpKind::Register => {
                        let val: u64 = self.get_val(instruction, 0)?;
                        self.set_val(instruction, 1, (val as u128) << 64)?;
                    }
                    OpKind::Memory => todo!(),
                    _ => unsafe { unreachable_unchecked() },
                },
                Mnemonic::Movaps | Mnemonic::Movdqa | Mnemonic::Movups => {
                    let val: u128 = self.get_val(instruction, 1)?;
                    self.set_val(instruction, 0, val).unwrap();
                }

                /*
                        +---------------------------------+
                        | Kernel interfacing Instructions |
                        +---------------------------------+
                */
                Mnemonic::Syscall => {
                    self.handle_syscall(self.get_reg(Register::RAX));
                }
                x => todo!("unsupported opcode: {x:?}"),
            };
        }
    }

    fn handle_syscall(&mut self, nr: usize) {
        match nr {
            // brk
            12 => {
                let rdi: u64 = self.get_reg(Register::RDI);
                if rdi == 0 {
                    self.set_reg(self.memory.cur_alc.0, Register::RAX);
                } else {
                    // ignore deallocations for now
                    if let Some(addr) = self.memory.allocate(rdi as usize - self.memory.cur_alc.0) {
                        self.set_reg(addr.0, Register::RAX)
                    }
                    // allocating memory failed
                    else {
                        self.set_reg(u64::MAX, Register::RAX)
                    }
                }
                println!(
                    "brk({rdi:#x}) -> {:#x}",
                    self.get_reg::<u64, 8>(Register::RAX)
                );
            }
            // arch_prctl (ignore this for now and see where it takes us)
            158 => {
                // we failed
                self.set_reg(u64::MAX, Register::RAX)
            }
            x => todo!("syscall {x}"),
        }
    }
    /// perform a logical or arithmetic operation, given by `f`,on the given operands
    /// currently it will only support doing an operation on the first 2 ops
    /// it also assumes that they both are equal in size
    #[inline]
    pub fn do_loar_op<T: Primitive<BYTES>, F: FnMut(T, T) -> T, const BYTES: usize>(
        &mut self,
        instruction: Instruction,
        mut f: F,
    ) -> Result<(), ()>
    where
        <T as TryFrom<u16>>::Error: Debug,
        <T as TryFrom<u32>>::Error: Debug,
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
        <T as TryInto<u16>>::Error: Debug,
        <T as TryInto<u32>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        // TODO: make the caller responsible for giving the right operands
        let rhs: T = self.get_val::<T, BYTES>(instruction, 1)?;
        let lhs: T = self.get_val::<T, BYTES>(instruction, 0)?;
        let new_lhs = f(lhs, rhs);
        self.set_val(instruction, 0, new_lhs)
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
    ) -> Result<(), ()>
    where
        <T as TryInto<u16>>::Error: Debug,
        <T as TryInto<u32>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        let opkind = instruction.op_kind(index);
        match opkind {
            OpKind::Register => {
                let reg: Register = reg_from_op_reg(instruction.op_register(index)).unwrap();
                Ok(self.set_reg(val, reg))
            }
            OpKind::Memory => {
                let address: usize = self.calc_addr(instruction);
                self.memory.write_primitive(Virtaddr(address), val)
            }
            _ => unsafe { unreachable_unchecked() },
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
            // call   QWORD PTR [r12+r14*8]
            // if that is the case, then multiply the value stored in the register (r14 in the above)
            // with its scale (8 in the above case)
            // and add the resulting value to the displacement
            if let Some(index_reg) = reg_from_op_reg(mem.memory_index()) {
                let scale = mem.memory_index_scale() as usize;
                addr = addr.wrapping_add(scale * self.get_reg::<usize, 8>(index_reg));
            }
            // check if there is a base register indexing the memory
            // if that is the case, add the value stored in the register to the current address
            // example:
            // call   QWORD PTR [r12+r14*8]
            // here r12 is the base register
            if let Some(base_reg) = reg_from_op_reg(mem.memory_base()) {
                // this can be wrapping, for example you can have
                // cmp    QWORD PTR [rdi-0x8],0x0
                // substracting some displacement (i.e. doing a wrapping add (I could be wrong here))
                addr = addr.wrapping_add(self.get_reg::<usize, 8>(base_reg));
            }
            addr
        }
    }

    #[cfg(debug_assertions)]
    #[inline]
    /// pretty print the whole register state
    fn trace(&self) {
        print!(
            "\x1b[1;92m  RIP:   \x1b[0m {:#x} -> ",
            self.get_reg::<u64, 8>(Register::RIP)
        );
        if let Ok(inst_buf) = self.memory.peek(
            Virtaddr(self.get_reg::<usize, 8>(Register::RIP)),
            16,
            PERM_EXEC,
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
        println!(
            "\x1b[1;92m  RFLAGS:\x1b[0m {:0>12b}",
            self.get_reg::<u64, 8>(Register::RFLAGS)
        );
        // pretty print the gprs
        for reg in (Register::RAX as u8)..=(Register::RSP as u8) {
            let reg = unsafe { core::mem::transmute::<u8, Register>(reg) };
            let mut val = self.get_reg::<u64, 8>(reg);
            print!("\x1b[1;32m  {:?}:\x1b[0m {:#x}", reg, val);
            let mut depth = 0;
            while let Ok(new_val) = self
                .memory
                .read_primitive::<8>(Virtaddr(usize::try_from(val).unwrap()))
            {
                val = u64::from_ne_bytes(new_val);
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
        // for reg in (Register::Xmm0 as u8)..=(Register::Xmm15 as u8) {
        //     let reg = unsafe { core::mem::transmute::<u8, Register>(reg) };
        //     let val = self.get_reg::<u64, 8>(reg);
        //     print!("\x1b[1;32m  {:06?}:\x1b[0m {:#x}", reg, val);
        // }
        println!()
    }
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
    /// Flag register <br\>    
    /// the flags are as outlined [here](https://en.wikipedia.org/wiki/FLAGS_register/) <br\>
    /// mask: `1 << 0` Carry flag <br\>
    /// mask: `1 << 1` reserverd (should be 1) <br\>
    /// mask: `1 << 2` Parity flag <br\>
    /// mask: `1 << 3` Reserved <br\>
    /// mask: `1 << 4` Auxilliary Carry flag <br\>
    /// mask: `1 << 5` Reserved <br\>
    /// mask: `1 << 6` Zero flag <br\>
    /// mask: `1 << 7` Sign flag <br\>
    /// mask: `1 << 8` Trap flag <br\>
    /// mask: `1 << 9` Interrupt enable flagi <\br>
    /// mask: `1 << 10` direction flag <\br>
    /// mask: `1 << 11` overflow flag <\br>
    RFLAGS,
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
    /// 16 bit hight bytes of `EAX`
    AH,
    /// general purpose register
    /// 16 bit hight bytes of `ECX`
    CH,
    /// general purpose register
    /// 16 bit hight bytes of `EDX`
    DH,
    /// general purpose register
    /// 16 bit hight bytes of `EBX`
    BH,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Bitness {
    Eight = 8,
    Sixteen = 16,
    ThirtyTwo = 32,
    SixtyFour = 64,
    HundredTwentyEigth = 128,
}
#[inline]
fn reg_from_op_reg(reg: iced_x86::Register) -> Option<Register> {
    use self::Register::*;
    use iced_x86::Register;
    match reg {
        Register::None => None,
        Register::RAX => Some(RAX),
        Register::EAX => Some(RAX),
        Register::AL => Some(RAX),
        Register::RCX => Some(RCX),
        Register::ECX => Some(RCX),
        Register::CH => Some(CH),
        Register::RDX => Some(RDX),
        Register::EDX => Some(RDX),
        Register::DX => Some(RDX),
        Register::DL => Some(RDX),
        Register::DH => Some(DH),
        Register::RBX => Some(RBX),
        Register::EBX => Some(RBX),
        Register::RSP => Some(RSP),
        Register::RBP => Some(RBP),
        Register::EBP => Some(RBP),
        Register::RSI => Some(RSI),
        Register::ESI => Some(RSI),
        Register::SIL => Some(RSI),
        Register::RDI => Some(RDI),
        Register::EDI => Some(RDI),
        Register::R8 => Some(R8),
        Register::R8D => Some(R8),
        Register::R9 => Some(R9),
        Register::R9D => Some(R9),
        Register::R10 => Some(R10),
        Register::R10D => Some(R10),
        Register::R10L => Some(R10),
        Register::R11 => Some(R11),
        Register::R11D => Some(R11),
        Register::R12 => Some(R12),
        Register::R12D => Some(R12),
        Register::R13 => Some(R13),
        Register::R13D => Some(R13),
        Register::R14 => Some(R14),
        Register::R14D => Some(R14),
        Register::R15 => Some(R15),
        Register::R15D => Some(R15),
        Register::EIP => Some(RIP),
        Register::RIP => Some(RIP),
        Register::XMM0 => Some(Xmm0),
        Register::XMM1 => Some(Xmm1),
        x => todo!("implement register {x:?}"),
    }
}

#[inline]
fn bitness(instr: Instruction) -> Bitness {
    match instr.op0_kind() {
        OpKind::Register => match instr.op0_register() {
            // https://stackoverflow.com/questions/1753602/what-are-the-names-of-the-new-x86-64-processors-registers
            iced_x86::Register::R8D
            | iced_x86::Register::R9D
            | iced_x86::Register::R10D
            | iced_x86::Register::R11D
            | iced_x86::Register::R12D
            | iced_x86::Register::R13D
            | iced_x86::Register::R14D
            | iced_x86::Register::R15D => Bitness::ThirtyTwo,
            iced_x86::Register::AL
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
            | iced_x86::Register::DIL => Bitness::Eight,
            iced_x86::Register::R10L => Bitness::Eight,
            iced_x86::Register::AX
            | iced_x86::Register::CX
            | iced_x86::Register::DX
            | iced_x86::Register::BX
            | iced_x86::Register::SP
            | iced_x86::Register::BP
            | iced_x86::Register::SI
            | iced_x86::Register::DI => Bitness::Sixteen,
            iced_x86::Register::EAX
            | iced_x86::Register::ECX
            | iced_x86::Register::EDX
            | iced_x86::Register::EBX
            | iced_x86::Register::ESP
            | iced_x86::Register::EBP
            | iced_x86::Register::ESI
            | iced_x86::Register::EDI
            | iced_x86::Register::EIP => Bitness::ThirtyTwo,
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
            iced_x86::Register::XMM0 => Bitness::HundredTwentyEigth,
            x => todo!("{x:?}"),
        },
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
