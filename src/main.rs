use anyhow::{anyhow, bail, Result};
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::ffi::CString;
use std::{fs, io, path::Path};
use structopt::StructOpt;
use termion::{event::Key, input::MouseTerminal, raw::IntoRawMode, screen::AlternateScreen};
use tui::{backend::TermionBackend, Terminal};

mod app;
mod display;
mod event;
mod net;
#[path = "bpf/.output/p2pflow.skel.rs"]
mod p2pflow;

use app::*;
use display::*;
use event::*;
use p2pflow::*;

type PeerV4 = p2pflow_bss_types::peer_v4_t;
type PeerV6 = p2pflow_bss_types::peer_v6_t;
type ValueType = p2pflow_bss_types::value_t;

unsafe impl Plain for PeerV4 {}
unsafe impl Plain for PeerV6 {}
unsafe impl Plain for ValueType {}

#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
    /// glibc path
    #[structopt(long, short, default_value = "/lib/x86_64-linux-gnu/libc.so.6")]
    glibc: String,
    /// refresh interval in milliseconds (unused)
    #[structopt(long, short, default_value = "250")]
    interval: u64,
    /// process name
    #[structopt(long, short, default_value = "geth")]
    process: String,
    /// only IPv4 peer connections
    #[structopt(long, short = "4")]
    ipv4: bool,
    /// only IPv6 peer connections
    #[structopt(long, short = "6")]
    ipv6: bool,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn get_symbol_address(so_path: &str, fn_name: &str) -> Result<usize> {
    let path = Path::new(so_path);
    let buffer = fs::read(path)?;
    let file = object::File::parse(buffer.as_slice())?;

    let mut symbols = file.dynamic_symbols();
    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or(anyhow!("symbol not found"))?;

    Ok(symbol.address() as usize)
}

fn main() -> Result<()> {
    let opts = Command::from_args();

    let mut skel_builder = P2pflowSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    let str = CString::new(opts.process.clone()).unwrap();
    let mut buf: [i8; 16] = [0; 16];

    let buf_ptr = buf.as_mut_ptr();

    unsafe {
        buf_ptr.copy_from(str.as_ptr(), 16);
    }

    open_skel.rodata().process_name = buf;

    let mut skel = open_skel.load()?;
    let _address = get_symbol_address(&opts.glibc, "getaddrinfo")?;

    skel.attach()?;

    let maps = skel.maps();
    let trackers_v4 = maps.trackers_v4();
    let trackers_v6 = maps.trackers_v6();

    let stdout = io::stdout().into_raw_mode()?;
    let stdout = MouseTerminal::from(stdout);
    let stdout = AlternateScreen::from(stdout);
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let events = Events::new();
    let mut app = App::new(opts.process);

    if !opts.ipv6 {
        app.set_v4_peers(trackers_v4);
    }
    if !opts.ipv4 {
        app.set_v6_peers(trackers_v6);
    }

    app.resolver.start();

    loop {
        app.refresh();
        app.items.sort(app.sort_key);

        draw_terminal(&mut terminal, &mut app)?;

        match events.next()? {
            Event::Input(key) => match key {
                Key::Char('q') | Key::Esc => {
                    break;
                }
                Key::Char('r') => {
                    app.first();
                    if let SortKey::TotalRx = app.sort_key {
                        app.sort_key = SortKey::None
                    } else {
                        app.sort_key = SortKey::TotalRx;
                    }
                }
                Key::Char('t') => {
                    app.first();
                    if let SortKey::TotalTx = app.sort_key {
                        app.sort_key = SortKey::None
                    } else {
                        app.sort_key = SortKey::TotalTx;
                    }
                }
                Key::Down | Key::Char('j') => {
                    app.next();
                }
                Key::Up | Key::Char('k') => {
                    app.previous();
                }
                _ => {}
            },
            Event::Tick => {}
        }
    }

    Ok(())
}
