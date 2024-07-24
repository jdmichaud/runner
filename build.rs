fn get_git_hash() -> String {
  use std::process::Command;

  let branch_output = Command::new("git")
    .arg("rev-parse")
    .arg("--abbrev-ref")
    .arg("HEAD")
    .output()
    .unwrap();
  let branch_output = String::from_utf8_lossy(&branch_output.stdout);
  let branch = branch_output.lines().next().unwrap();
  let commit_output = Command::new("git")
    .arg("rev-parse")
    .arg("--verify")
    .arg("--short")
    .arg("HEAD")
    .output()
    .unwrap();
  let commit_output = String::from_utf8_lossy(&commit_output.stdout);
  if let Some(commit) = commit_output.lines().next() {
    format!("{}-{}", branch, commit)
  } else {
    format!("{}", branch)
  }
}

fn main() {
  let git_hash = get_git_hash();
  println!("cargo:rustc-env=GIT_HASH={}", &git_hash);
}
