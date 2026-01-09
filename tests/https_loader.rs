use anyhow::{Context, Result};
use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn runs_http_elf() -> Result<()> {
    let temp = TempDir::new("elf-rs-test")?;
    let root = temp.path();

    let hello_c = root.join("hello.c");
    fs::write(
        &hello_c,
        b"#include <stdio.h>\nint main(){puts(\"hello\");return 0;}\n",
    )
    .context("write hello.c")?;

    let hello_bin = root.join("hello");
    run(Command::new("gcc").arg(&hello_c).arg("-o").arg(&hello_bin)).context("compile hello.c")?;

    let port = pick_free_port()?;
    let server = start_http_server(port, root)?;
    let _guard = ChildGuard(server);
    wait_for_port(port)?;

    let loader = std::env::var("CARGO_BIN_EXE_elf-rs")
        .unwrap_or_else(|_| default_loader_path().to_string_lossy().into_owned());

    let url = format!("http://127.0.0.1:{}/hello", port);
    let output = Command::new(&loader)
        .arg(url)
        .output()
        .context("run loader")?;

    assert!(
        output.status.success(),
        "loader failed: {:?}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello\n");
    Ok(())
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd.status().context("spawn command")?;
    if !status.success() {
        anyhow::bail!("command failed with {}", status);
    }
    Ok(())
}

fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind port")?;
    let port = listener.local_addr().context("local addr")?.port();
    drop(listener);
    Ok(port)
}

fn start_http_server(port: u16, root: &Path) -> Result<Child> {
    let script = format!(
        "import http.server, os\n\
root = os.environ['ROOT']\n\
port = int(os.environ['PORT'])\n\
os.chdir(root)\n\
handler = http.server.SimpleHTTPRequestHandler\n\
httpd = http.server.ThreadingHTTPServer(('127.0.0.1', port), handler)\n\
httpd.serve_forever()\n"
    );

    let mut cmd = Command::new("python3");
    cmd.arg("-u")
        .arg("-c")
        .arg(script)
        .env("ROOT", root)
        .env("PORT", port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    cmd.spawn().context("start http server")
}

fn wait_for_port(port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let deadline = SystemTime::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(&addr).is_ok() {
            return Ok(());
        }
        if SystemTime::now() > deadline {
            anyhow::bail!("timeout waiting for http server");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{}-{}", prefix, nanos));
        fs::create_dir_all(&path).context("create temp dir")?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn default_loader_path() -> PathBuf {
    let mut p = PathBuf::from("target/debug/elf-rs");
    if cfg!(windows) {
        p.set_extension("exe");
    }
    p
}
