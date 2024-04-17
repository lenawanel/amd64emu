#![feature(portable_simd)]
#![feature(thread_local)]
#![feature(unchecked_math)]
#![feature(unchecked_shifts)]
pub mod emu;
pub mod mmu;
pub mod primitive;
mod symbol_table;

#[cfg(test)]
mod tests {
    use super::*;
    // #[test]
    // fn bddisam_test() {
    //     // lea    rdi,[rdx+rax*8+0x8]
    //     let inst: [u8; 5] = [0x48, 0x8d, 0x7c, 0xc2, 0x8];
    //     let decoded_inst =
    //         bddisasm::DecodedInstruction::decode(&inst, bddisasm::DecodeMode::Bits64).unwrap();
    //     println!("{:?}", decoded_inst.mnemonic());
    //     let _ = decoded_inst.operands();
    // }

    #[test]
    fn emu_run_test() {
        let mut emu = emu::Emu::new(1024 * 1024 * 16);
        emu.load("./tests/a.out");
        emu.run_emu().unwrap();
    }
}
