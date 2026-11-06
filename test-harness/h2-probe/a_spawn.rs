// D1(a) with std::process::Command::spawn after unshare(NEWUSER)+maps+unshare(NEWPID). Scratch. — Muse
use std::process::Command;
extern "C" { fn unshare(flags: i32) -> i32; fn getuid() -> u32; fn getgid() -> u32; }
const NEWUSER: i32 = 0x10000000; const NEWPID: i32 = 0x20000000;
fn main() {
    let (u, g) = unsafe { (getuid(), getgid()) };
    assert_eq!(unsafe { unshare(NEWUSER) }, 0, "unshare user: {}", std::io::Error::last_os_error());
    std::fs::write("/proc/self/setgroups", "deny").unwrap();
    std::fs::write("/proc/self/uid_map", format!("0 {u} 1")).unwrap();
    std::fs::write("/proc/self/gid_map", format!("0 {g} 1")).unwrap();
    assert_eq!(unsafe { unshare(NEWPID) }, 0, "unshare pid: {}", std::io::Error::last_os_error());
    let mut c = Command::new("sh").arg("-c").arg("grep NSpid /proc/self/status").spawn().unwrap();
    println!("Child::id()={}", c.id());
    c.wait().unwrap();
}
