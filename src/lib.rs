#![feature(portable_simd)]
#![feature(thread_local)]
#![feature(bigint_helper_methods)]
#![feature(debug_closure_helpers)]
pub mod emu;
pub mod mmu;
pub mod primitive;
mod symbol_table;

#[cfg(test)]
mod tests {
    use std::{io::Write, process::Command};

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

    /*#[test]
     fn emu_run_test() {
        let mut emu = emu::Emu::new(1024 * 1024 * 16);
        emu.load("./tests/a.out");
        emu.run_emu().unwrap();
    } */
    #[test]
    fn test_cmp_1_0() {
        test_flags_hw(
            2, "
        mov rax, 1
        cmp rax, 0
        ",
        );
    }

    #[test]
    fn test_cmp_1_11() {
        test_flags_hw(0, 
            "mov rax, 1
        cmp rax, 11",
        );
    }
    #[test]
    fn test_sub_1_11() {
        test_flags_hw(1,&format!(
            "
        mov rax, {}
        sub rax, {}
        ",
            u64::MAX - 1,
            1
        ));
    }

    fn test_flags_hw(id: u64, code: &str) {
        let code = format!(
            "
        
    global    _start

    section   .text
_start:
        {code}
        pushf
        mov       rax, 60                 ; system call for exit
        pop       rdi                     ; exit code rflags
        syscall                           ; invoke operating system to exit
        "
        );
        let mut file = std::fs::File::create(format!("test_flags{id}.asm")).unwrap();
        file.write_all(code.as_bytes()).unwrap();

        drop(file);
        assert!(Command::new("./assemble.sh")
            .arg(format!("test_flags{id}.asm"))
            .spawn()
            .unwrap()
            .wait()
            .unwrap()
            .success());

        let flags_hw = Command::new(format!("./test_flags{id}"))
            .spawn()
            .unwrap()
            .wait()
            .unwrap()
            .code()
            .unwrap();

        let mut emu = emu::Emu::new(1024 * 1024 * 16);
        emu.load(format!("test_flags{id}"));
        std::fs::remove_file(format!("test_flags{id}.asm")).unwrap();
        std::fs::remove_file(format!("test_flags{id}")).unwrap();

        match emu.run_emu() {
            Err(emu::ExecErr::Exit { code, .. }) => assert_eq!(code as i32, flags_hw),
            x => panic!("{x:?}"),
        }
    }
}
