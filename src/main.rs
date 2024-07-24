// cargo run -- serve tasks.test.yml
// cargo run -- list
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use std::os::unix::process::ExitStatusExt;
use std::os::unix::net::{UnixStream, UnixListener};
use std::env;
use std::path::PathBuf;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use clap::{Parser, Subcommand};
use std::io::prelude::*;

const DEFAULT_CONFIG: &str = include_str!("../default-config.yml");

/// A bookmark manager
#[derive(Debug, Parser)]
#[command(
  name = format!("{} ({} {})", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"), env!("GIT_HASH")),
  version = "",
  max_term_width = 100,
)]
struct Opt {
  /// YAML configuration file to use.
  /// If not provided, use the file ~/.config/runner/config.yaml.
  /// If the file does not exists, use default embedded config (see --print-config)
  #[arg(short, long, value_name = "FILE", verbatim_doc_comment)]
  config: Option<PathBuf>,
  /// Print the used configuration and exit.
  /// You can use this option to initialize the default config file with:
  ///   mkdir -p ~/.config/bookmark/
  ///   bookmark --print-config ~/.config/bookmark/config.yaml
  #[arg(long, verbatim_doc_comment)]
  print_config: bool,

  #[command(subcommand)]
  command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
  /// Adds a bookmark
  Serve { task_file_path: PathBuf },
  /// List the jobs
  List,
}

#[derive(Debug, Serialize, Deserialize)]
enum Request {
  /// List the jobs
  List,
}

#[derive(Debug, Serialize, Deserialize)]
enum Response {
  /// Job list
  List { jobs: Vec<JobRepr> },
  None,
}


#[derive(Debug, Serialize, Deserialize)]
struct ConfigRepr {
}

#[derive(Debug)]
struct Config {
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Task {
  current_dir: String,
  command: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
enum ExitStatusRepr {
  Code(u8),
  Signal(i32),
  None,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct JobRepr {
  task: Task,
  pid: u32,
  status: ExitStatusRepr,
  stdout_path: String,
  stderr_path: String,
}

#[derive(Debug)]
struct Job {
  task: Task,
  child: std::process::Child,
  stdout_path: String,
  stderr_path: String,
}


// struct DefaultFolders<'a> {
//   config: &'a Config,
// }

// impl<'a> DefaultFolders<'a> {
//   pub fn new(config: &'a Config) -> Self {
//     Self { config }
//   }

//   pub fn get_data_folder(self: &Self) -> Result<PathBuf> {
//     let default_config_data_path: String =
//       env::var("XDG_DATA_HOME").unwrap_or(env::var("HOME")? + "/.local/share") + "/bookmark/";
//     std::fs::create_dir_all(&default_config_data_path)?;
//     let path = std::path::PathBuf::from(&default_config_data_path);
//     return Ok(path);
//   }
// }

fn get_config(opt: &Opt) -> Result<Config> {
  let default_config_file_path: String =
    env::var("XDG_CONFIG_HOME").unwrap_or(env::var("HOME")? + "/.config/") +
    "/" + env!("CARGO_PKG_NAME") + "/config.yaml";

  // Load the config. We first check if a config file was provided as an option
  let config_content: String = if let Some(config_file) = &opt.config {
    // Try to load it
    match std::fs::read_to_string(&config_file) {
      Ok(config) => config,
      Err(e) => anyhow::bail!("error: {e}: {}", config_file.display()),
    }
  } else {
    // Otherwise, try the standard path
    if std::fs::metadata(std::path::Path::new(&default_config_file_path)).is_ok() {
      // Try to load it
      match std::fs::read_to_string(&default_config_file_path) {
        Ok(config) => config,
        Err(e) => anyhow::bail!("error: {e}: {}", default_config_file_path),
      }
    } else {
      // Otherwise, just use the embedded config file
      DEFAULT_CONFIG.to_string()
    }
  };
  if opt.print_config {
    // Print the content of the configuration file and exit
    println!("{}", config_content);
    std::process::exit(0);
  }

  let config_repr: ConfigRepr = serde_yaml::from_str(&config_content)?;

  let config = Config {};

  Ok(config)
}

fn start_task(task: &Task) -> Result<Job> {
  use shlex::Shlex;

  let mut split = Shlex::new(&task.command);
  let prog: String = split.next().unwrap();

  let current_dir = shellexpand::full(&task.current_dir).unwrap();
  if !std::path::Path::new(current_dir.as_ref()).exists() {
    anyhow::bail!("provided current directory for {}: {} does not exists", &prog, &current_dir);
  }

  use std::iter;
  use rand::{Rng, thread_rng};
  use rand::distributions::Alphanumeric;

  let mut rng = rand::thread_rng();
  let random_suffix: String = std::iter::repeat(())
    .map(|()| rng.sample(Alphanumeric))
    .map(char::from)
    .take(5)
    .collect();  let mut stdout_path = std::env::temp_dir();
  stdout_path.push("out".to_string() + &random_suffix);
  let stdout = std::fs::File::create(&stdout_path)?;
  let mut stderr_path = std::env::temp_dir();
  stderr_path.push("err".to_string() + &random_suffix);
  let stderr = std::fs::File::create(&stderr_path)?;
  let child = match std::process::Command::new(&prog)
    .stdout(stdout)
    .stderr(stderr)
    .stdin(std::process::Stdio::null())
    .args(split.collect::<Vec<String>>())
    .current_dir(current_dir.as_ref())
    .spawn() {
      Ok(child) => child,
      Err(e) => anyhow::bail!("could not start {}: {}", &prog, e),
    };

  Ok(Job {
    task: task.clone(),
    child: child,
    stdout_path: stdout_path.to_path_buf().to_string_lossy().to_string(),
    stderr_path: stderr_path.to_path_buf().to_string_lossy().to_string(),
  })
}

fn signal_to_string(signal: i32) -> String {
  (match signal {
    1 => "SIGHUP",
    2 => "SIGINT",
    3 => "SIGQUIT",
    4 => "SIGILL",
    5 => "SIGTRAP",
    6 => "SIGIOT",
    7 => "SIGBUS",
    8 => "SIGFPE",
    9 => "SIGKILL",
    10 => "SIGUSR1",
    11 => "SIGSEGV",
    12 => "SIGUSR2",
    13 => "SIGPIPE",
    14 => "SIGALRM",
    15 => "SIGTERM",
    16 => "SIGSTKFLT",
    17 => "SIGCHLD",
    18 => "SIGCONT",
    19 => "SIGSTOP",
    20 => "SIGTSTP",
    21 => "SIGTTIN",
    22 => "SIGTTOU",
    23 => "SIGURG",
    24 => "SIGXCPU",
    25 => "SIGXFSZ",
    26 => "SIGVTALRM",
    27 => "SIGPROF",
    28 => "SIGWINCH",
    29 => "SIGIO",
    30 => "SIGPWR",
    _ => "UNKNOWN SIGNAL",
  }).to_string()
}

fn render(jobs: &Vec<JobRepr>) {
  println!("{: <37} {: <13} {: <13} {: <6} {: <7}", "COMMAND", "STDOUT", "STDERR", "PID", "STATUS");
  for job in jobs {
    let status = match job.status {
      ExitStatusRepr::Code(code) => code.to_string(),
      ExitStatusRepr::Signal(signal) => signal_to_string(signal),
      ExitStatusRepr::None => "Running".to_string(),
    };
    let command_truncated = if job.task.command.len() > 36 {
      (&job.task.command[..33]).to_string() + "..."
    } else {
      job.task.command.to_string()
    };
    println!("{: <37} {: <13} {: <13} {: <6} {: <7}",
      command_truncated, job.stdout_path, job.stderr_path, job.pid.to_string(), status);
  }
}

fn get_status(child: &mut std::process::Child) -> ExitStatusRepr {
  if let Ok(status) = child.try_wait() {
    if let Some(exit_status) = status {
      if let Some(exit_code) = exit_status.code() {
        ExitStatusRepr::Code((exit_code & 0xFF).try_into().unwrap())
      } else if let Some(signal) = exit_status.signal() {
        ExitStatusRepr::Signal(signal)
      } else {
        unreachable!()
      }
    } else {
      ExitStatusRepr::None
    }
  } else {
    ExitStatusRepr::None
  }
}

impl Drop for Job {
  fn drop(&mut self) {
    println!("kill {}", self.child.id());
    let _ = self.child.kill();
  }
}

fn serve(config: &Config, task_file_path: &PathBuf, socket_path: &str) -> Result<()> {
  // Starting the tasks
  let task_file = std::fs::read_to_string(task_file_path)
    .or_else(|e| Err(anyhow::anyhow!("could not open {:?}: {}", &task_file_path, e)))?;
  let tasks: Vec<Task> = serde_yaml::from_str(&task_file)
    .or_else(|e| Err(anyhow::anyhow!("could not parse {:?}: {}", &task_file_path, e)))?;
  let jobs: std::sync::Arc<std::sync::Mutex<Vec<Job>>> = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
  {
    let mut jobs = jobs.lock().unwrap();
    for task in tasks {
      let _ = jobs.push(start_task(&task)?);
    }
    println!("started with {} jobs", jobs.len());

    if std::path::Path::new(&socket_path).exists() {
      std::fs::remove_file(&socket_path)?;
    }
  }
  // Listening to command
  let listener = UnixListener::bind(socket_path)
    .or_else(|e| Err(anyhow::anyhow!("could not bind to socket {}: {}", socket_path, e)))?;

  let jobsclone = jobs.clone();
  ctrlc::set_handler(move || {
    println!("shutting down...");
    print!("killing ");
    for job in jobsclone.lock().unwrap().iter_mut() {
      print!("{} ", job.child.id());
      let _ = job.child.kill();
    }
    println!("");
    std::process::exit(0);
  }).expect("Error setting Ctrl-C handler");

  loop {
    println!("Listening to {socket_path}");
    match listener.accept() {
      Ok((mut socket, addr)) => {
        // Wait for the client to send a command for 3 seconds and then timeout
        if let Err(e) = socket.set_read_timeout(Some(std::time::Duration::new(3, 0))) {
          eprintln!("warning: could not set a timeout on {}: {}", socket_path, e);
        }
        println!("Connected to {addr:?}");
        match receive(&mut socket)? {
          Request::List => {
            let mut sjobs: Vec<JobRepr> = vec![];
            for job in jobs.lock().unwrap().iter_mut() {
              sjobs.push(JobRepr {
                task: job.task.clone(),
                pid: job.child.id(),
                status: get_status(&mut job.child),
                stdout_path: job.stdout_path.clone(),
                stderr_path: job.stderr_path.clone(),
              });
            }

            if let Err(e) = send(&mut socket, &Response::List { jobs: sjobs }) {
              eprintln!("warning: error writing to client ({e:?})");
              continue;
            }
          }
        }
      }
      Err(e) => {
        println!("warning: could not connect: {e:?}");
        break;
      }
    };
  }
  // let mut stream = UnixStream::connect(socket_path)?;
  Ok(())
}

fn send<T: Serialize>(socket: &mut UnixStream, request: &T) -> Result<()> {
  // TODO try to avoid allocating a temporary string here
  let request_string: String = serde_json::to_string(request)?;
  socket.write_all(request_string.as_bytes())?;
  socket.write_all(b"\n")?;
  Ok(())
}

fn receive<T: for<'a> Deserialize<'a>>(socket: &mut UnixStream) -> Result<T> {
  let mut response = String::new();
  let mut reader = std::io::BufReader::new(socket);
  reader.read_line(&mut response)?;
  let response: T = serde_json::from_str(&response)?;
  Ok(response)
}

fn main() -> Result<()> {
  let opt = Opt::parse();
  let config = &get_config(&opt)?;

  let socket_path = "/tmp/runner-daemon.socket";

  // We treat the commands here
  let response = match &opt.command {
    Some(Command::Serve { task_file_path }) => {
      serve(&config, &task_file_path, socket_path)?;
      None
    }
    Some(Command::List) | None => {
      // By default, just lists the tasks
      let mut socket = UnixStream::connect(socket_path)?;
      send(&mut socket, &Request::List{})?;
      receive(&mut socket)?
    }
  };

  match response {
    Some(Response::List { jobs }) => render(&jobs),
    Some(Response::None) | None => {},
  }

  Ok(())
}
