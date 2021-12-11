use anyhow::{anyhow, bail, Result};
use async_std::task::block_on;
use libbpf_rs::Map;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::ffi::CString;
use std::{fs, io, path::Path};
use structopt::StructOpt;
use termion::{event::Key, input::MouseTerminal, raw::IntoRawMode, screen::AlternateScreen};
use tui::{backend::TermionBackend, widgets::TableState, Terminal};

mod display;
mod event;
mod net;
#[path = "bpf/.output/p2pflow.skel.rs"]
mod p2pflow;

use display::*;
use event::*;
use net::*;
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

#[derive(Clone)]
pub struct App<'a> {
    process_name: String,
    state: TableState,
    v4_peers: Option<&'a Map>,
    v6_peers: Option<&'a Map>,
    resolver: Resolver,
}

impl<'a> App<'a> {
    fn new(process_name: String) -> App<'a> {
        App {
            process_name,
            state: TableState::default(),
            v4_peers: None,
            v6_peers: None,
            resolver: block_on(Resolver::new()),
        }
    }

    fn set_v4_peers(&mut self, trackers_v4: &'a Map) {
        self.v4_peers = Some(trackers_v4);
    }

    fn set_v6_peers(&mut self, trackers_v6: &'a Map) {
        self.v6_peers = Some(trackers_v6);
    }

    fn table_len(&self) -> usize {
        let mut len = 0;
        if let Some(v4_peers) = self.v4_peers {
            len += v4_peers.keys().count();
        }

        if let Some(v6_peers) = self.v6_peers {
            len += v6_peers.keys().count();
        }

        len
    }

    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.table_len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.table_len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
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
        draw_terminal(&mut terminal, &mut app)?;

        match events.next()? {
            Event::Input(key) => match key {
                Key::Char('q') | Key::Esc => {
                    break;
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
