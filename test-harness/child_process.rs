//! Bounded subprocess capture, included only by test targets.

use std::io::{self, Read, Seek};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub(crate) struct TestChild {
    pub(crate) child: Child,
    stdout: tempfile::NamedTempFile,
    stderr: tempfile::NamedTempFile,
}

impl TestChild {
    pub(crate) fn spawn(command: &mut Command) -> io::Result<Self> {
        // Files avoid both pipe-capacity deadlocks and waiting for EOF from
        // a grandchild that inherited a captured stream. Reopen gives the
        // writer its own cursor, so readiness reads cannot rewind its writes.
        let stdout = tempfile::NamedTempFile::new()?;
        let stderr = tempfile::NamedTempFile::new()?;
        let child = command
            .stdin(Stdio::null())
            .stdout(stdout.reopen()?)
            .stderr(stderr.reopen()?)
            .spawn()?;
        Ok(Self {
            child,
            stdout,
            stderr,
        })
    }

    pub(crate) fn stdout(&mut self) -> io::Result<Vec<u8>> {
        read_capture(&mut self.stdout)
    }

    pub(crate) fn output(&mut self, timeout: Duration) -> io::Result<Output> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(Output {
                    status,
                    stdout: self.stdout()?,
                    stderr: read_capture(&mut self.stderr)?,
                });
            }
            if start.elapsed() >= timeout {
                self.child.kill()?;
                self.child.wait()?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "test subprocess exceeded {timeout:?}\nstdout: {}\nstderr: {}",
                        String::from_utf8_lossy(&self.stdout()?),
                        String::from_utf8_lossy(&read_capture(&mut self.stderr)?),
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        // Also clean up on assertion failures before output() is called.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_capture(file: &mut tempfile::NamedTempFile) -> io::Result<Vec<u8>> {
    file.rewind()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}
