#![forbid(unused_macros)]
// Regression control retained as an accepted gap by Keystone ruling #3:
// retyping an already inventoried descriptor is not another inventory event.
use std::os::fd::OwnedFd;
type Approved = std::fs::File;

pub fn question_mark(fd: OwnedFd) -> Result<(), Approved> {
    Err::<(), OwnedFd>(fd)?;
    Ok(())
}
pub fn generic_retype<T: From<OwnedFd>>(fd: OwnedFd) -> Result<(), T> {
    Err::<(), OwnedFd>(fd)?;
    Ok(())
}
fn approved_consumer(_: Result<(), Approved>) {}
pub fn inferred_caller(fd: OwnedFd) {
    approved_consumer(generic_retype(fd));
}
pub fn explicit_from(fd: OwnedFd) -> Approved { Approved::from(fd) }
pub fn explicit_into(fd: OwnedFd) -> Approved { fd.into() }
