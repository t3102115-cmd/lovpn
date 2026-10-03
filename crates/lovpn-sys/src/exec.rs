//! Fixed-tool command execution. No shell, no PATH lookup, no inherited environment.
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT: u64 = 1 << 20;

/// The only programs LoVPN will ever execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Program {
    Ip,
    Wg,
    Nft,
    Resolvectl,
}

impl Program {
    fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Wg => "wg",
            Self::Nft => "nft",
            Self::Resolvectl => "resolvectl",
        }
    }
}

pub struct Cmd {
    pub program: Program,
    pub args: Vec<String>,
    /// Secret-bearing input (WireGuard config, nft batch). Zeroized after use.
    pub stdin: Option<Zeroizing<Vec<u8>>>,
}

impl Cmd {
    pub fn new(program: Program, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(ToString::to_string).collect(),
            stdin: None,
        }
    }

    pub fn with_stdin(mut self, input: Zeroizing<Vec<u8>>) -> Self {
        self.stdin = Some(input);
        self
    }
}

pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
}

/// Sanitized: names the step, never arguments, output or secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecError {
    ToolMissing,
    Failed(&'static str),
}

/// Executes fixed commands. Tests substitute a fake host.
pub trait Runner: Send + Sync {
    fn run(&self, cmd: &Cmd, step: &'static str) -> Result<CmdOutput, ExecError>;
}

pub struct SystemRunner;

fn find_program(program: Program) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(program.name()))
        .find(|path| path.is_file())
}

impl Runner for SystemRunner {
    fn run(&self, cmd: &Cmd, step: &'static str) -> Result<CmdOutput, ExecError> {
        let path = find_program(cmd.program).ok_or(ExecError::ToolMissing)?;
        let failed = |_| ExecError::Failed(step);
        let mut child = Command::new(path)
            .args(&cmd.args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(failed)?;
        let stdin_thread = cmd.stdin.as_ref().and_then(|input| {
            let mut pipe = child.stdin.take()?;
            let data = Zeroizing::new(input.to_vec());
            Some(std::thread::spawn(move || {
                let _ = pipe.write_all(&data);
            }))
        });
        let stdout = child.stdout.take();
        let reader = std::thread::spawn(move || {
            let mut text = Vec::new();
            if let Some(out) = stdout {
                let mut limited = out.take(MAX_OUTPUT);
                let _ = limited.read_to_end(&mut text);
                let _ = std::io::copy(&mut limited.into_inner(), &mut std::io::sink());
            }
            text
        });
        let start = Instant::now();
        let status = loop {
            match child.try_wait().map_err(failed)? {
                Some(status) => break status,
                None if start.elapsed() > COMMAND_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ExecError::Failed(step));
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        };
        if let Some(thread) = stdin_thread {
            let _ = thread.join();
        }
        let stdout = reader.join().map_err(|_| ExecError::Failed(step))?;
        Ok(CmdOutput {
            success: status.success(),
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
        })
    }
}
