use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_std::task::block_on;
use libbpf_rs::{Map, MapFlags};
use tui::widgets::TableState;

use crate::{net::Resolver, PeerV4, PeerV6, ValueType};

// #[derive(Clone)]
pub struct App<'a> {
    pub process_name: String,
    pub state: TableState,
	pub paused: bool,
	pub sort_key: SortKey,
    pub items: Items,
    pub v4_peers: Option<&'a Map>,
    pub v6_peers: Option<&'a Map>,
    pub resolver: Resolver,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub ip: IpAddr,
    pub port: u16,
    pub tot_rx: u64,
    pub tot_tx: u64,
}

pub struct Items {
    pub vec: Vec<Item>,
}
#[derive(Clone, Copy)]
pub enum SortKey {
    TotalRx,
    TotalTx,
	None
}

impl Items {
    fn new() -> Items {
        Items { vec: Vec::new() }
    }

    pub fn sort(&mut self, key: SortKey) {
        match key {
            SortKey::TotalRx => self
                .vec
                .sort_by(|a, b| b.tot_rx.cmp(&a.tot_rx)),
            SortKey::TotalTx => self
                .vec
                .sort_by(|a, b| b.tot_tx.cmp(&a.tot_tx)),
			_ => {}
        }
    }
}

impl<'a> App<'a> {
    pub fn new(process_name: String) -> App<'a> {
        App {
            process_name,
            state: TableState::default(),
			paused: true,
			sort_key: SortKey::None,
            items: Items::new(),
            v4_peers: None,
            v6_peers: None,
            resolver: block_on(Resolver::new()),
        }
    }

    pub fn refresh(&mut self) {
        self.items.vec.clear();
        self.set_v4_peers(self.v4_peers.unwrap());
        self.set_v6_peers(self.v6_peers.unwrap());
    }

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

                let kb_in = value.bytes_in / 1024;
                let kb_out = value.bytes_out / 1024;
                let ip = IpAddr::V4(Ipv4Addr::from(key.daddr.to_be()));

                self.items.vec.push(Item {
                    ip: ip,
                    port: key.dport,
                    tot_rx: kb_in,
                    tot_tx: kb_out,
                });
            })
            .collect()
    }

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

                let kb_in = value.bytes_in / 1024;
                let kb_out = value.bytes_out / 1024;

                let ipv6 = Ipv6Addr::from(key.daddr.to_be());
                let ip = ipv6.to_ipv4().unwrap();

                self.items.vec.push(Item {
                    ip: ip.into(),
                    port: key.dport,
                    tot_rx: kb_in,
                    tot_tx: kb_out,
                });
            })
            .collect()
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

	pub fn first(&mut self) {
		self.state.select(Some(0));
	}
}
