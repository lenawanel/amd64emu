use amd64_emu::emu;

pub fn main() {
    let mut emu = emu::Emu::new(1024 * 1024 * 8);
    let path = std::env::args().nth(1).unwrap();
    emu.load(path);
    let res = emu.run_emu();
    #[cfg(debug_assertions)]
    {
        emu.trace();
        emu.print_stack::<u64, 8>(emu.stack_depth);
    }
    println!("exec result: {res:#x?}");
    println!("cur_alc: {:#x?}", emu.memory.cur_alc);
}
