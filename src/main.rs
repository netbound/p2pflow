use anyhow::{anyhow, bail, Result};
use libbpf_rs::MapFlags;
use object::Object;
use object::ObjectSymbol;
use plain::Plain;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use structopt::StructOpt;

#[path = "bpf/.output/p2pflow.skel.rs"]
mod p2pflow;
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
    /// process name
    #[structopt(long, short, default_value = "geth")]
    pname: String,
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

    // TODO load process name into rodata
    // Check length (max 20)
    // open_skel.rodata().process_name = opts.pname.into_bytes().iter().map(|&c| c as i8);
    // mem::transmute::<[u8], i8>(opts.pname.into_bytes()).as_slice();
    open_skel.rodata().p2p_port = opts.port;

    let mut skel = open_skel.load()?;
    let _address = get_symbol_address(&opts.glibc, "getaddrinfo")?;

    skel.attach()?;

    let maps = skel.maps();
    let trackers_v4 = maps.trackers_v4();
    let trackers_v6 = maps.trackers_v6();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(1));
        let mut size = 0u32;

        for k in trackers_v4.keys() {
            let mut key = PeerV4::default();
            let mut value = ValueType::default();
            plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
            let val = trackers_v4.lookup(&k, MapFlags::ANY).unwrap().unwrap();
            plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");
            println!(
                "Peer: {:?}:{} - Out: {} MB, In: {} MB",
                Ipv4Addr::from(key.daddr),
                key.dport,
                value.bytes_out / 1024,
                value.bytes_in / 1024,
            );
            size += 1;
        }

        for k in trackers_v6.keys() {
            let mut key = PeerV6::default();
            let mut value = ValueType::default();
            plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
            let val = trackers_v6.lookup(&k, MapFlags::ANY).unwrap().unwrap();
            plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");
            println!(
                "Peer: {:?}:{} - Out: {} MB, In: {} MB",
                Ipv6Addr::from(key.daddr),
                key.dport,
                value.bytes_out / 1024,
                value.bytes_in / 1024,
            );
            size += 1;
        }
        println!("Map length {}", size);
    }

    Ok(())
}
