use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use async_std::task::block_on;
use libbpf_rs::{Map, MapFlags};
use tui::widgets::TableState;

use crate::{
    net::{RateMonitor, Resolver},
    PeerV4, PeerV6, ValueType,
};

#[derive(Clone)]
pub struct App<'a> {
    pub process_name: String,
    pub state: TableState,
    pub sort_key: SortKey,
    pub items: Items,
    pub prev_bytes: HashMap<String, (u64, u64)>,
    pub v4_peers: Option<&'a Map>,
    pub v6_peers: Option<&'a Map>,
    pub resolver: Resolver,
    pub rate_monitor: RateMonitor,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub ip: IpAddr,
    pub is_v4: bool,
    pub port: u16,
    // Total KiB received
    pub tot_rx: u64,
    // Total KiB sent
    pub tot_tx: u64,
    // Receive rate in bps
    pub rx_rate: u64,
    // Send rate in bps
    pub tx_rate: u64,
}

#[derive(Clone)]
pub struct Items {
    pub vec: Vec<Item>,
}

#[derive(Clone, Copy)]
pub enum SortKey {
    TotalRx,
    TotalTx,
    RxRate,
    TxRate,
    None,
}

impl Items {
    fn new() -> Items {
        Items { vec: Vec::new() }
    }

    pub fn sort(&mut self, key: SortKey) {
        match key {
            SortKey::TotalRx => self.vec.sort_by(|a, b| b.tot_rx.cmp(&a.tot_rx)),
            SortKey::TotalTx => self.vec.sort_by(|a, b| b.tot_tx.cmp(&a.tot_tx)),
            _ => {}
        }
    }
}

impl<'a> App<'a> {
    pub fn new(process_name: String) -> App<'a> {
        App {
            process_name,
            state: TableState::default(),
            sort_key: SortKey::None,
            items: Items::new(),
            prev_bytes: HashMap::new(),
            v4_peers: None,
            v6_peers: None,
            resolver: block_on(Resolver::new()),
            rate_monitor: RateMonitor::new(),
        }
    }

    /// Starts the DNS resolver and rate monitor
    pub fn start(&mut self) {
        self.resolver.start();
        self.rate_monitor.start(self.items.clone());
    }

    /// Clears all the items in current state, and reloads them
    /// from the BPF maps.
    pub fn refresh(&mut self) {
        self.items.vec.clear();
        if let Some(v4_peers) = self.v4_peers {
            self.set_v4_peers(v4_peers);
        }
        if let Some(v6_peers) = self.v6_peers {
            self.set_v6_peers(v6_peers);
        }
    }

    /// Sets the v4_peers BPF map and parses entries to load into the items array.
    pub fn set_v4_peers(&mut self, v4_peers: &'a Map) {
        self.v4_peers = Some(v4_peers);

        v4_peers
            .keys()
            .map(|k| {
                let mut key = PeerV4::default();
                let mut value = ValueType::default();

                plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
                let val = v4_peers.lookup(&k, MapFlags::ANY).unwrap().unwrap();
                plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");

                let b_rx = value.bytes_in;
                let b_tx = value.bytes_out;
                let ip = IpAddr::V4(Ipv4Addr::from(key.daddr.to_be()));

                let (tx_rate, rx_rate) = self.rate_monitor.get_rates(&format!("{}:{}", ip, key.dport));

                // TODO: this resets rates to 0 every time we refresh,
                // so we can't display proper rates
                self.items.vec.push(Item {
                    ip: ip,
                    is_v4: true,
                    port: key.dport,
                    tot_rx: b_rx,
                    tot_tx: b_tx,
                    rx_rate,
                    tx_rate,
                });
            })
            .collect()
    }

    /// Sets the v6_peers BPF map and parses entries to load into the items array.
    pub fn set_v6_peers(&mut self, v6_peers: &'a Map) {
        self.v6_peers = Some(v6_peers);

        v6_peers
            .keys()
            .map(|k| {
                let mut key = PeerV6::default();
                let mut value = ValueType::default();

                plain::copy_from_bytes(&mut key, &k).expect("Couldn't decode key");
                let val = v6_peers.lookup(&k, MapFlags::ANY).unwrap().unwrap();
                plain::copy_from_bytes(&mut value, &val).expect("Couldn't decode value");

                let b_rx = value.bytes_in;
                let b_tx = value.bytes_out;

                let ipv6 = Ipv6Addr::from(key.daddr.to_be());
                let ip = ipv6.to_ipv4().unwrap();

                let (tx_rate, rx_rate) = self.rate_monitor.get_rates(&format!("{}:{}", ip, key.dport));

                self.items.vec.push(Item {
                    ip: ip.into(),
                    is_v4: false,
                    port: key.dport,
                    tot_rx: b_rx,
                    tot_tx: b_tx,
                    rx_rate,
                    tx_rate,
                });
            })
            .collect()
    }

    /// Returns the length of all the items.
    fn table_len(&self) -> usize {
        self.items.vec.len()
    }

    /// Selects the next item in the table.
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

    /// Selects the previous item in the table.
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

    pub fn first(&mut self) {
        self.state.select(Some(0));
    }
}
