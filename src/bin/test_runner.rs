use amd64_emu::emu;

pub fn main() {
    let mut emu = emu::Emu::new(1024 * 1024 * 16);
    emu.load("./tests/a.out");
    emu.run_emu().unwrap();
}
