use core::fmt::Debug;
use std::path::Path;

// this is impossible to because of https://github.com/bitdefender/bddisasm/issues/82 ;(
// use bddisasm::{operand::Operands, DecodedInstruction, OpInfo, Operand};
use iced_x86::{Decoder, Instruction, Mnemonic, OpKind};

use crate::{
    mmu::{Virtaddr, MMU},
    primitive::Primitive,
};

pub struct Emu {
    memory: MMU,
    registers: [u64; 21],
    simd_registers: [u128; 15],
}

impl Emu {
    pub fn load<P: AsRef<Path>>(&mut self, file: P) {
        let (rip, frame) = self.memory.load(file);
        self.set_reg(rip.0 as u64, Register::RIP);
        self.set_reg(frame.0 as u64, Register::RSP);
        // self.set_reg(frame.0 as u64 - 8, Register::RBP);

        // Set up the program name
        let argv = self
            .memory
            .allocate(8)
            .expect("Failed to allocate program name");
        self.memory
            .write_from(argv, b"test\0")
            .expect("Failed to write program name");

        macro_rules! push {
            ($expr:expr) => {
                let sp = self.get_reg::<u64, 8>(Register::RSP) as usize;
                self.memory
                    .write_primitive(Virtaddr(sp), $expr)
                    .expect("Push failed");
                self.set_reg(sp - core::mem::size_of_val(&$expr) as usize, Register::RSP);
                // self.set_reg(sp, Register::RBP);
            };
        }

        // Set up the initial program stack state
        push!(0u64); // Auxp
        push!(0u64); // Envp
        push!(0u64); // Argv end
        push!(argv.0); // Argv
        push!(1u64); // Argc
                     // push!(0u64);
    }

    pub fn new(size: usize) -> Self {
        Self {
            memory: MMU::new(size),
            registers: [0; 21],
            simd_registers: [0; 15],
        }
    }

    #[inline]
    pub fn set_reg<T: Primitive<BYTES>, const BYTES: usize>(&mut self, val: T, register: Register)
    where
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        if (register as u8) < self.registers.len() as u8 {
            self.registers[register as usize] = val.to_u64();
        } else {
            self.simd_registers[register as usize - self.registers.len()] = val.try_into().unwrap();
        }
    }

    // TODO: make this less disgusting
    #[inline]
    pub fn get_reg<T: Primitive<BYTES>, const BYTES: usize>(&self, register: Register) -> T
    where
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
    {
        if (register as u8) < self.registers.len() as u8 {
            self.registers[register as usize].try_into().unwrap()
        } else {
            self.simd_registers[register as usize - self.registers.len()]
                .try_into()
                .unwrap()
        }
    }

    #[inline]
    pub fn get_val<T: Primitive<BYTES>, const BYTES: usize>(
        &self,
        instruction: Instruction,
        index: u32,
    ) -> Result<T, ()>
    where
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
            OpKind::Immediate8 => todo!(),
            OpKind::Immediate16 => todo!(),
            OpKind::Immediate32 => todo!(),
            OpKind::Immediate64 => todo!(),
            OpKind::Immediate8to16 => todo!(),
            OpKind::Immediate8to32 => todo!(),
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

    pub fn run_emu(&mut self) -> Result<(), ()> {
        'next_instr: loop {
            // we have to look ahead 16 bytes into memory since that's the maximum size of x86 instructions

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
            macro_rules! push {
                ($expr:expr) => {
                    let sp = self.get_reg::<u64, 8>(Register::RSP) as usize;
                    println!("pushing to: {sp:#x}");
                    self.memory.write_primitive(Virtaddr(sp), $expr)?;
                    self.set_reg(sp - core::mem::size_of_val(&$expr) as usize, Register::RSP);
                };
            }

            println!("executing: {:#x?}", self.get_reg::<usize, 8>(Register::RIP));

            // set rip to the next instruction
            // this needs to be done here to correctly handle
            // instructions wiht offsets
            inc_reg!(instruction.len(), Register::RIP);
            match instruction.mnemonic() {
                Mnemonic::Add => {
                    // treat this as usize for now.
                    // this is wrong so
                    // TODO: handle diffrent op sizes here
                    self.do_loar_op::<usize, _, 8>(instruction, std::ops::Add::add)?;
                }
                Mnemonic::And => {
                    // treat this as usize for now.
                    // this is wrong so
                    // TODO: handle diffrent op sizes here
                    self.do_loar_op::<usize, _, 8>(instruction, std::ops::BitAnd::bitand)?;
                }
                Mnemonic::Call => {
                    // get the new ip
                    let new_ip: usize = self.get_val::<usize, 8>(instruction, 0)?;
                    push!(self.get_reg::<usize, 8>(Register::RIP));
                    self.set_reg(new_ip, Register::RIP);
                    continue 'next_instr;
                }
                Mnemonic::Cmp => {
                    let lhs: usize = self.get_val(instruction, 0)?;
                    let rhs: usize = self.get_val(instruction, 0)?;
                    // XXX: actually make this correct
                    match lhs.cmp(&rhs) {
                        // unset the carry flag and the zero flag if above
                        std::cmp::Ordering::Greater => self.set_reg(
                            /* !*/
                            (0 << 6) | (0 << 0), /*& self.get_reg::<u64, 8>(Register::RFLAGS)*/
                            Register::RFLAGS,
                        ),
                        // set the zero flag if eq
                        std::cmp::Ordering::Equal => self.set_reg(1 << 6, Register::RFLAGS),
                        // unset the carry flag and set the zero flag if less
                        std::cmp::Ordering::Less => self.set_reg(
                            (0 << 6) | (1 << 0), /*& self.get_reg::<u64, 8>(Register::RFLAGS)*/
                            Register::RFLAGS,
                        ),
                    }
                }
                Mnemonic::Endbr64 => {
                    // do nothing here for now
                }
                Mnemonic::Jne => {
                    if self.get_reg::<u64, 8>(Register::RFLAGS) & (1 << 6) == 0 {
                        let new_ip: usize = self.get_val::<usize, 8>(instruction, 0)?;
                        self.set_reg(new_ip, Register::RIP);
                        continue 'next_instr;
                    }
                }
                Mnemonic::Lea => {
                    // calling set_val and matching is overkill here
                    // so TODO: inline the set_reg call performed here
                    self.set_val(instruction, 0, self.calc_addr(instruction))?;
                }
                Mnemonic::Mov => {
                    // this is some hacky shit
                    // also not really respecting bitness, so
                    // TODO: respect bitness here
                    self.do_loar_op::<usize, _, 8>(instruction, |_, x| x)?;
                }
                Mnemonic::Movsxd => {
                    // this is some hacky shit, I love it
                    // also not really respecting bitness, so
                    // TODO: respect bitness here
                    // also let's hope that this sign extends
                    self.do_loar_op::<isize, _, 8>(instruction, |x, _| x)?;
                }
                Mnemonic::Sub => {
                    // also not really respecting bitness, so
                    // TODO: respect bitness here
                    self.do_loar_op::<isize, _, 8>(instruction, core::ops::Sub::sub)?;
                }
                Mnemonic::Pop => {
                    macro_rules! pop {
                        ($exp:expr) => {{
                            let sp = self.get_reg::<u64, 8>(Register::RSP) as usize;
                            self.set_reg(sp + $exp as usize, Register::RSP);
                            self.memory.read_primitive(Virtaddr(sp))?
                        }};
                    }
                    // TODO: do bitness stuff here
                    let val = usize::from_ne_bytes(pop!(8));
                    self.set_val(instruction, 0, val)?;
                }
                Mnemonic::Push => {
                    // TODO: do bitness stuff here
                    let val: usize = self.get_val::<_, 8>(instruction, 0)?;
                    println!("after getting value to push");
                    push!(val);
                }
                Mnemonic::Xor => {
                    // treat this as usize for now.
                    // this is wrong so
                    // TODO: handle diffrent op sizes here
                    self.do_loar_op::<usize, _, 8>(instruction, core::ops::BitOr::bitor)?;
                }
                Mnemonic::Nop => {
                    // it's literally a Nop
                }
                x => todo!("unsupported opcode: {x:?}"),
            };
            // set the instruction pointer to the next instruction
        }
    }

    /// perform a logical or arithmetic operation, given by `f`,on the given operands
    /// currently it will only support doing an operation on the first 2 ops
    /// it also assumes that they both are equal in size
    #[inline]
    pub fn do_loar_op<T: Primitive<BYTES>, F: Fn(T, T) -> T, const BYTES: usize>(
        &mut self,
        instruction: Instruction,
        f: F,
    ) -> Result<(), ()>
    where
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        // TODO: make the caller responsible for giving the right operands
        let rhs: T = self.get_val::<T, BYTES>(instruction, 1)?;
        let lhs: T = self.get_val::<T, BYTES>(instruction, 0)?;
        println!("lhs: {lhs:#x?} rhs: {rhs:#x?}");
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
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        let opkind = instruction.op_kind(index);
        match opkind {
            OpKind::Register => {
                let reg: Register = reg_from_op_reg(instruction.op_register(index)).unwrap();
                Ok(self.set_reg(val, reg))
            }
            OpKind::NearBranch16 => todo!(),
            OpKind::NearBranch32 => todo!(),
            OpKind::NearBranch64 => todo!(),
            OpKind::FarBranch16 => todo!(),
            OpKind::FarBranch32 => todo!(),
            OpKind::Memory => {
                let address: usize = self.calc_addr(instruction);
                self.memory.write_primitive(Virtaddr(address), val)
            }
            x => todo!("{x:?}"),
        }
    }

    #[inline]
    /// resolve the address an instruction uses
    // XXX: I think there only can be one
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
                addr += scale * self.get_reg::<usize, 8>(index_reg);
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
}

#[inline]
fn reg_from_op_reg(reg: iced_x86::Register) -> Option<Register> {
    use self::Register::*;
    use iced_x86::Register;
    match reg {
        Register::None => None,
        Register::RAX => Some(RAX),
        Register::EAX => Some(RAX),
        Register::RCX => Some(RCX),
        Register::ECX => Some(RCX),
        Register::RDX => Some(RDX),
        Register::RBX => Some(RBX),
        Register::RSP => Some(RSP),
        Register::RBP => Some(RBP),
        Register::EBP => Some(RBP),
        Register::RSI => Some(RSI),
        Register::ESI => Some(RSI),
        Register::RDI => Some(RDI),
        Register::R8 => Some(R8),
        Register::R8D => Some(R8),
        Register::R9 => Some(R9),
        Register::R10 => Some(R10),
        Register::R11 => Some(R11),
        Register::R12 => Some(R12),
        Register::R13 => Some(R13),
        Register::R14 => Some(R14),
        Register::R15 => Some(R15),
        Register::R15D => Some(R15),
        Register::EIP => Some(RIP),
        Register::RIP => Some(RIP),
        x => todo!("implement register {x:?}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    /// the intruction pointer
    RIP = 16,
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
    RFLAGS = 17,
    /// general purpose register
    RAX = 0,
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
    // Segment Register (16 bit wide)
    CS = 18,
    // Segment Register (16 bit wide)
    FS,
    // Segment Register (16 bit wide)
    GS,

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
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum RegisterBitness {
    Eight = 8,
    Sixteen = 16,
    ThirtyTwo = 32,
    SixtyFour = 64,
    HundredTwentyEigth = 128,
}
