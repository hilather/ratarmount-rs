#![forbid(unused_macros)]
use rustix::fs::{openat, openat2, Mode, OFlags, ResolveFlags, CWD};
pub fn probe() {
    let _ = openat(CWD, "fixture", OFlags::CREATE | OFlags::EXCL, Mode::RUSR | Mode::WUSR);
    let _ = openat2(CWD, "fixture", OFlags::CREATE | OFlags::EXCL, Mode::RUSR | Mode::WUSR, ResolveFlags::empty());
    let mut builder = std::fs::OpenOptions::new();
    builder.create(true).create_new(true);
    let _ = std::fs::create_dir("fixture");
    let _ = std::fs::File::create("fixture");
}
