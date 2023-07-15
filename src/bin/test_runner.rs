use amd64_emu::emu;

pub fn main() {
    let mut emu = emu::Emu::new(1024 * 1024 * 16);
    emu.load("./tests/a.out");
    let _ = emu.run_emu();
    #[cfg(debug_assertions)]
    {
        emu.trace();
        emu.print_stack::<u64, 8>(emu.stack_depth);
    }
}
