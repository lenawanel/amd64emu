use core::fmt::Debug;
use std::path::Path;

// this is impossible to because of https://github.com/bitdefender/bddisasm/issues/82 ;(
use bddisasm::{operand::Operands, DecodedInstruction, OpInfo, Operand};

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
        // let buf = [0u8; BYTES];
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
        operand: Operand,
    ) -> Result<T, ()>
    where
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
    {
        match operand.info {
            bddisasm::OpInfo::None => unreachable!("accesed an operand which does not exist"),
            bddisasm::OpInfo::Reg(reg) => {
                let reg: Register = reg_from_op_reg(reg);
                Ok(self.get_reg(reg))
            }
            bddisasm::OpInfo::Mem(mem) => {
                let address: usize = self.calc_addr(mem);
                self.memory
                    .read_primitive(Virtaddr(address))
                    .map(T::from_ne_bytes)
            }
            bddisasm::OpInfo::Imm(imm) => T::try_from(imm).map_err(|_| ()),
            bddisasm::OpInfo::Offs(offset) => {
                T::try_from(self.get_reg::<u64, 8>(Register::RIP).wrapping_add(offset))
                    .map_err(|_| ())
            }
            bddisasm::OpInfo::Addr(_) => todo!(),
            bddisasm::OpInfo::Const(cons) => T::try_from(cons).map_err(|_| ()),
            bddisasm::OpInfo::Bank => todo!(),
        }
        // todo!()
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
            let instruction = DecodedInstruction::decode(&inst_buf, bddisasm::DecodeMode::Bits64)
                .map_err(|_| ())?;

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
                    self.memory.write_primitive(Virtaddr(sp), $expr)?;
                    self.set_reg(sp - core::mem::size_of_val(&$expr) as usize, Register::RSP);
                };
            }

            println!("executing: {:#x?}", self.get_reg::<usize, 8>(Register::RIP));

            // set rip to the next instruction
            // this needs to be done here to correctly handle
            // instructions wiht offsets
            inc_reg!(instruction.length(), Register::RIP);
            match instruction.mnemonic() {
                bddisasm::Mnemonic::Adcx => todo!(),
                bddisasm::Mnemonic::Add => todo!(),
                bddisasm::Mnemonic::Addpd => todo!(),
                bddisasm::Mnemonic::Addps => todo!(),
                bddisasm::Mnemonic::Addsd => todo!(),
                bddisasm::Mnemonic::Addss => todo!(),
                bddisasm::Mnemonic::Addsubpd => todo!(),
                bddisasm::Mnemonic::Addsubps => todo!(),
                bddisasm::Mnemonic::And => {
                    let operands = instruction.operands();
                    // treat this as usize for now.
                    // this is wrong so
                    // TODO: handle diffrent op sizes here
                    self.do_loar_op::<usize, _, 8>(&operands, std::ops::BitAnd::bitand)?;
                }
                bddisasm::Mnemonic::Andn => todo!(),
                bddisasm::Mnemonic::Andnpd => todo!(),
                bddisasm::Mnemonic::Andnps => todo!(),
                bddisasm::Mnemonic::Andpd => todo!(),
                bddisasm::Mnemonic::Andps => todo!(),
                bddisasm::Mnemonic::Callnr => {
                    // get the new ip
                    let new_ip: usize = self.get_val::<usize, 8>(instruction.operands()[0])?;
                    push!(self.get_reg::<usize, 8>(Register::RIP));
                    self.set_reg(new_ip, Register::RIP);
                    continue 'next_instr;
                }
                bddisasm::Mnemonic::Cmovcc => todo!(),
                bddisasm::Mnemonic::Cmp => todo!(),
                bddisasm::Mnemonic::Cpuid => todo!(),
                bddisasm::Mnemonic::Dec => todo!(),
                bddisasm::Mnemonic::Div => todo!(),
                bddisasm::Mnemonic::Divpd => todo!(),
                bddisasm::Mnemonic::Divps => todo!(),
                bddisasm::Mnemonic::Divsd => todo!(),
                bddisasm::Mnemonic::Divss => todo!(),
                bddisasm::Mnemonic::Endbr => {
                    // do nothing here for now
                }
                bddisasm::Mnemonic::Idiv => todo!(),
                bddisasm::Mnemonic::Imul => todo!(),
                bddisasm::Mnemonic::Inc => todo!(),
                bddisasm::Mnemonic::Jmpe => todo!(),
                bddisasm::Mnemonic::Jmpfd => todo!(),
                bddisasm::Mnemonic::Jmpfi => todo!(),
                bddisasm::Mnemonic::Jmpni => todo!(),
                bddisasm::Mnemonic::Jmpnr => todo!(),
                bddisasm::Mnemonic::Jcc => todo!(),
                bddisasm::Mnemonic::Lea => {
                    let ops_lookup = instruction.operand_lookup();
                    let op_reg = ops_lookup.dest(0).unwrap();
                    let op_mem = ops_lookup.mem(0).unwrap();
                    if let OpInfo::Mem(mem) = op_mem.info {
                        self.set_val(op_reg, self.calc_addr(mem))?;
                    } else {
                        unreachable!()
                    }
                }
                bddisasm::Mnemonic::Mov => {
                    let operands = instruction.operands();
                    // this is some hacky shit
                    // also not really respecting bitness, so
                    // TODO: respect bitness here
                    self.do_loar_op::<usize, _, 8>(&operands, |x, _| x)?;
                }
                bddisasm::Mnemonic::Movapd => todo!(),
                bddisasm::Mnemonic::Movaps => todo!(),
                bddisasm::Mnemonic::Movbe => todo!(),
                bddisasm::Mnemonic::Movd => todo!(),
                bddisasm::Mnemonic::Movddup => todo!(),
                bddisasm::Mnemonic::Movdqu => todo!(),
                bddisasm::Mnemonic::Movq => todo!(),
                bddisasm::Mnemonic::Movq2dq => todo!(),
                bddisasm::Mnemonic::Movs => todo!(),
                bddisasm::Mnemonic::Movsd => todo!(),
                bddisasm::Mnemonic::Movshdup => todo!(),
                bddisasm::Mnemonic::Movsldup => todo!(),
                bddisasm::Mnemonic::Movsxd => {
                    let operands = instruction.operands();
                    // this is some hacky shit
                    // also not really respecting bitness, so
                    // TODO: respect bitness here
                    // also let's hope that this sign extends
                    self.do_loar_op::<isize, _, 8>(&operands, |x, _| x)?;
                }
                bddisasm::Mnemonic::Mul => todo!(),
                bddisasm::Mnemonic::Mulpd => todo!(),
                bddisasm::Mnemonic::Mulps => todo!(),
                bddisasm::Mnemonic::Mulsd => todo!(),
                bddisasm::Mnemonic::Mulss => todo!(),
                bddisasm::Mnemonic::Mulx => todo!(),
                bddisasm::Mnemonic::Neg => todo!(),
                bddisasm::Mnemonic::Nop => {}
                bddisasm::Mnemonic::Not => todo!(),
                bddisasm::Mnemonic::Or => todo!(),
                bddisasm::Mnemonic::Retf => todo!(),
                bddisasm::Mnemonic::Retn => todo!(),
                bddisasm::Mnemonic::Sub => {
                    let operands = instruction.operands();
                    // this is some hacky shit
                    // also not really respecting bitness, so
                    // TODO: respect bitness here
                    self.do_loar_op::<isize, _, 8>(&operands, core::ops::Sub::sub)?;
                }
                bddisasm::Mnemonic::Syscall => todo!(),
                bddisasm::Mnemonic::Test => todo!(),
                bddisasm::Mnemonic::Pop => {
                    macro_rules! pop {
                        ($exp:expr) => {{
                            let sp = self.get_reg::<u64, 8>(Register::RSP) as usize;
                            self.set_reg(sp + $exp as usize, Register::RSP);
                            self.memory.read_primitive(Virtaddr(sp))?
                        }};
                    }
                    // TODO: do bitness stuff here
                    let val = usize::from_ne_bytes(pop!(8));
                    self.set_val(instruction.operands()[0], val)?;
                }
                bddisasm::Mnemonic::Push => {
                    // TODO: do bitness stuff here
                    let val: usize = self.get_val::<_, 8>(instruction.operands()[0])?;
                    push!(val);
                }
                bddisasm::Mnemonic::Xor => {
                    let operands = instruction.operands();
                    // treat this as usize for now.
                    // this is wrong so
                    // TODO: handle diffrent op sizes here
                    self.do_loar_op::<usize, _, 8>(&operands, core::ops::BitOr::bitor)?;
                }
                bddisasm::Mnemonic::Xorpd => todo!(),
                bddisasm::Mnemonic::Xorps => todo!(),
                bddisasm::Mnemonic::Xrstor => todo!(),
                bddisasm::Mnemonic::Xrstors => todo!(),
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
        operands: &Operands,
        f: F,
    ) -> Result<(), ()>
    where
        <T as TryFrom<u64>>::Error: Debug,
        <T as TryFrom<u128>>::Error: Debug,
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        // TODO: make the caller responsible for giving the right operands
        let rhs: T = self.get_val::<T, BYTES>(operands[1])?;
        let lhs: T = self.get_val::<T, BYTES>(operands[0])?;
        let new_lhs = f(lhs, rhs);
        self.set_val(operands[0], new_lhs)
    }

    /// set an operand to a value.
    /// this will fail if we try writing to a memory region without the correct
    /// permissions
    #[inline]
    fn set_val<T: Primitive<BYTES>, const BYTES: usize>(
        &mut self,
        operand: Operand,
        val: T,
    ) -> Result<(), ()>
    where
        <T as TryInto<u64>>::Error: Debug,
        <T as TryInto<u128>>::Error: Debug,
    {
        match operand.info {
            bddisasm::OpInfo::None => unreachable!("accesed an operand which does not exist"),
            bddisasm::OpInfo::Reg(reg) => {
                let reg: Register = reg_from_op_reg(reg);
                Ok(self.set_reg(val, reg))
            }
            bddisasm::OpInfo::Mem(mem) => {
                let address: usize = self.calc_addr(mem);
                self.memory.write_primitive(Virtaddr(address), val)
            }
            bddisasm::OpInfo::Imm(_) => todo!(),
            bddisasm::OpInfo::Offs(_) => todo!(),
            bddisasm::OpInfo::Addr(_) => todo!(),
            bddisasm::OpInfo::Const(_) => unreachable!(),
            bddisasm::OpInfo::Bank => todo!(),
        }
    }

    fn calc_addr(&self, mem: bddisasm::OpMem) -> usize {
        if mem.is_rip_rel {
            // self.get_reg(Register::RIP);
            todo!("{mem:?}")
        } else if mem.is_direct {
            todo!("{mem:?}")
        } else {
            // just pretend like we're using the same register index as
            // bddisasm + 3
            let mut addr = self.get_reg(unsafe {
                let reg = core::mem::transmute::<u8, Register>(mem.base.unwrap() + 3);
                println!("base reg : {reg:?}");
                reg
            });
            println!("base reg addr: {addr:#x}");
            if let Some(index_reg) = mem.index {
                // by bddisasms doc
                // mem_index == Some(_) -> mem.scale == Some(_)
                // so we can just not check the unwrap here
                let scale = unsafe { mem.scale.unwrap_unchecked() } as usize;
                unsafe {
                    addr += scale
                        * self.get_reg::<usize, 8>(core::mem::transmute::<u8, Register>(index_reg));
                }
            }
            if let Some(displacement) = mem.disp {
                addr += displacement as usize;
            }
            addr
        }
    }
}

#[inline]
fn reg_from_op_reg(reg: bddisasm::OpReg) -> Register {
    match reg.kind {
        bddisasm::OpRegType::Gpr => unsafe {
            // let's just hope intel doc agrees with us
            let reg = std::mem::transmute::<u8, Register>(reg.index as u8);
            reg
        },
        bddisasm::OpRegType::Mmx => todo!(),
        bddisasm::OpRegType::Flg => Register::RFLAGS,
        bddisasm::OpRegType::Rip => Register::RIP,
        x => todo!("implement register {x}"),
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
