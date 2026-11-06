//! Child-process helpers: run a command with piped output and a wall-clock
//! timeout, std-only (a reader thread per pipe, `try_wait` polling).

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// What a finished (or killed) child produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    /// The exit code, or `None` when killed by a signal (including the timeout).
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Whether the timeout fired and the child was killed.
    pub timed_out: bool,
}

impl Captured {
    /// Whether the child exited 0.
    pub const fn success(&self) -> bool {
        matches!(self.code, Some(0))
    }

    /// A one-line failure description for an error message.
    pub fn describe_failure(&self) -> String {
        let status = if self.timed_out {
            "timed out".to_owned()
        } else {
            self.code.map_or_else(
                || "killed by a signal".to_owned(),
                |code| format!("exit {code}"),
            )
        };
        let stderr = self.stderr.trim();
        let stdout = self.stdout.trim();
        let detail = if stderr.is_empty() { stdout } else { stderr };
        if detail.is_empty() {
            status
        } else {
            format!("{status}: {}", tail_lines(detail, 15))
        }
    }
}

/// The last `count` lines of `text`, for error messages.
fn tail_lines(text: &str, count: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(count);
    lines[start..].join("\n")
}

/// Run `command` to completion with `stdin` fed from `input` (or `/dev/null` when
/// `None`), killing it after `timeout`. Output is decoded lossily — every consumer
/// here compares or prints text.
///
/// # Errors
/// The spawn itself failed (program missing, etc.).
pub fn run(
    mut command: Command,
    input: Option<&[u8]>,
    timeout: Duration,
) -> std::io::Result<Captured> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        let bytes = bytes.to_vec();
        // write on a thread so a child that stops reading can't wedge us
        thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }
    let stdout = child.stdout.take().map(spawn_reader);
    let stderr = child.stderr.take().map(spawn_reader);

    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(20));
    };
    // A child can hand its pipes to a grandchild that outlives it (an `ssh`
    // `ControlPersist` master backgrounding itself), so EOF may never come: give the
    // readers a short grace period after exit, then take what they have.
    let grace = Instant::now() + Duration::from_secs(2);
    let collect = |sink: Option<Sink>| {
        sink.map(|sink| {
            while !sink.done() && Instant::now() < grace {
                thread::sleep(Duration::from_millis(10));
            }
            sink.take()
        })
        .unwrap_or_default()
    };
    Ok(Captured {
        code: status.code(),
        stdout: collect(stdout),
        stderr: collect(stderr),
        timed_out,
    })
}

/// A pipe drained on a background thread into a shared buffer.
struct Sink {
    buffer: Arc<Mutex<Vec<u8>>>,
    done: Arc<AtomicBool>,
}

impl Sink {
    fn done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    fn take(&self) -> String {
        let bytes = self
            .buffer
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

fn spawn_reader<R: Read + Send + 'static>(mut pipe: R) -> Sink {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(AtomicBool::new(false));
    let (thread_buffer, thread_done) = (Arc::clone(&buffer), Arc::clone(&done));
    thread::spawn(move || {
        let mut chunk = [0_u8; 8192];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(mut guard) = thread_buffer.lock() {
                        guard.extend_from_slice(&chunk[..n]);
                    }
                }
            }
        }
        thread_done.store(true, Ordering::Release);
    });
    Sink { buffer, done }
}
