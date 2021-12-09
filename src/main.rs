use anyhow::{anyhow, bail, Result};
use libbpf_rs::Map;
use libbpf_rs::MapFlags;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{
    fs, io,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    vec::Vec,
};
use structopt::StructOpt;
use termion::{event::Key, input::MouseTerminal, raw::IntoRawMode, screen::AlternateScreen};
use tui::{
    backend::TermionBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Terminal,
};

mod event;
#[path = "bpf/.output/p2pflow.skel.rs"]
mod p2pflow;

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
    /// p2p port
    #[structopt(long, short, default_value = "30303")]
    port: u16,
    /// refresh interval in seconds
    #[structopt(long, short, default_value = "1")]
    interval: u64,
    /// process name
    #[structopt(long, short, default_value = "geth")]
    pname: String,
    /// only IPv4 peer connections
    #[structopt(long, short)]
    ipv4: bool,
    /// only IPv6 peer connections
    #[structopt(long, short)]
    ipv6: bool,
}

#[derive(Debug, Clone)]
enum PeerType {
    PeerV4,
    PeerV6,
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
struct App<'a> {
    state: TableState,
    v4_peers: Option<&'a Map>,
    v6_peers: Option<&'a Map>,
    // new_items: HashMap<PeerType, ValueType>,
}

impl<'a> App<'a> {
    fn new() -> App<'a> {
        App {
            state: TableState::default(),
            v4_peers: None,
            v6_peers: None,
            // new_items: HashMap::new(),
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

    // TODO: load process name into rodata
    open_skel.rodata().p2p_port = opts.port;

    let mut skel = open_skel.load()?;
    let _address = get_symbol_address(&opts.glibc, "getaddrinfo")?;

    skel.attach()?;

    // TODO: Size of maps doesn't change
    let maps = skel.maps();
    let trackers_v4 = maps.trackers_v4();
    let trackers_v6 = maps.trackers_v6();

    let stdout = io::stdout().into_raw_mode()?;
    let stdout = MouseTerminal::from(stdout);
    let stdout = AlternateScreen::from(stdout);
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let events = Events::new();
    let mut app = App::new();

    if !opts.ipv6 {
        app.set_v4_peers(trackers_v4);
    }
    if !opts.ipv4 {
        app.set_v6_peers(trackers_v6);
    }

    // What does this do?
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        terminal.draw(|f| {
            let rects = Layout::default()
                .constraints([Constraint::Percentage(100)].as_ref())
                .margin(1)
                .split(f.size());

            let selected_style = Style::default().add_modifier(Modifier::REVERSED);
            let normal_style = Style::default().add_modifier(Modifier::BOLD);
            let header_cells = ["IP address", "Port", "kB in", "kB out"]
                .iter()
                .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
            let header = Row::new(header_cells)
                .style(normal_style)
                .height(1)
                .bottom_margin(1);

            let mut rows = Vec::new();

            if let Some(v4_peers) = app.v4_peers {
                let mut v4_rows: Vec<Row> = v4_peers.keys().map(|k| {
                    let mut key = PeerV4::default();
                    let mut value = ValueType::default();

                    plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
                    let val = trackers_v4.lookup(&k, MapFlags::ANY).unwrap().unwrap();
                    plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");
                    let entry = vec![
                        Ipv4Addr::from(key.daddr).to_string(),
                        key.dport.to_string(),
                        (value.bytes_in / 1024).to_string(),
                        (value.bytes_out / 1024).to_string(),
                    ];

                    let cells = entry.iter().map(|c| Cell::from(c.clone()));
                    Row::new(cells).height(1)
                }).collect();

                rows.append(&mut v4_rows);
            }

            if let Some(v6_peers) = app.v6_peers {
                let mut v6_rows: Vec<Row> = v6_peers.keys().map(|k| {
                    let mut key = PeerV6::default();
                    let mut value = ValueType::default();

                    plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
                    let val = trackers_v6.lookup(&k, MapFlags::ANY).unwrap().unwrap();
                    plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");
                    let entry = vec![
                        Ipv6Addr::from(key.daddr).to_string(),
                        key.dport.to_string(),
                        (value.bytes_in / 1024).to_string(),
                        (value.bytes_out / 1024).to_string(),
                    ];

                    let cells = entry.iter().map(|c| Cell::from(c.clone()));
                    Row::new(cells).height(1)
                }).collect();

                rows.append(&mut v6_rows);
            }

            let t = Table::new(rows.into_iter())
                .header(header)
                .block(Block::default().borders(Borders::ALL).title("p2pflow"))
                .highlight_style(selected_style)
                // .highlight_symbol("* ")
                .widths(&[
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                    Constraint::Percentage(25),
                ]);
            f.render_stateful_widget(t, rects[0], &mut app.state);
        })?;

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
