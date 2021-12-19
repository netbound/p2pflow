use arraydeque::ArrayDeque;
use async_std::task::spawn;
use async_std_resolver::{proto::rr::Name, resolver_from_system_conf, AsyncStdResolver};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{mpsc, Arc, Mutex},
    time::Duration, thread,
};

use crate::app::{Items};

#[derive(Debug, Clone)]
pub struct Resolver {
    mappings: Arc<Mutex<HashMap<IpAddr, String>>>,
    resolver: AsyncStdResolver,
    tx: Option<mpsc::Sender<IpAddr>>,
}

impl<'a> Resolver {
    pub async fn new() -> Resolver {
        Resolver {
            mappings: Default::default(),
            resolver: resolver_from_system_conf().await.unwrap(),
            tx: None,
        }
    }

    pub fn start(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.tx = Some(tx);
        let resolver = self.resolver.clone();
        let mappings = self.mappings.clone();

        spawn(async move {
            loop {
                let rcv = rx.recv();
                if let Ok(ip) = rcv {
                    let resolver = resolver.clone();
                    let mappings = mappings.clone();
                    spawn(async move {
                        if let Ok(rev) = resolver.reverse_lookup(ip).await {
                            let name = rev.into_iter().next().unwrap_or(Name::new());
                            mappings.lock().unwrap().insert(ip, name.to_string());
                        }
                    });
                }
            }
        });
    }

    pub fn resolve_ip(&self, ip: IpAddr) -> String {
        if let Some(name) = self.mappings.lock().unwrap().get(&ip) {
            name.to_owned()
        } else {
            let tx = self.tx.clone();
            spawn(async move {
                if let Some(tx) = tx {
                    tx.send(ip).unwrap_or_default();
                }
            });

            "".to_string()
        }
    }
}

#[derive(Clone)]
pub struct RateMonitor {
    rates: Arc<Mutex<HashMap<String, (u64, u64)>>>,
}

impl RateMonitor {
    pub fn new() -> RateMonitor {
        RateMonitor {
            rates: Default::default(),
        }
    }

    /// Starts monitoring the items and calculates the bytes per second rate
    pub fn start(&mut self, items: Arc<Mutex<Items>>) {
        let rates = self.rates.clone();
        thread::spawn(move || {
            // Ring buffer to save previous stats
            let mut stats: HashMap<String, ArrayDeque<[(u64, u64); 10], arraydeque::Wrapping>> =
                HashMap::new();
            loop {
                for item in &mut items.lock().unwrap().vec {
                    let key = format!("{}:{}", item.ip, item.port);
                    if let Some(arr) = stats.get_mut(&key) {
                        arr.push_back((item.tot_tx, item.tot_rx));
                        let (mut tx_rate, mut rx_rate) = arr.back().unwrap_or(&(0, 0));
                        let last = arr.front().unwrap_or(&(0, 0));
                        // calculation:
                        // last item - first item = difference in bytes
                        // divide this by the number of items in the buffer (one added each second)
                        // and we have bytes per second.
                        tx_rate = (tx_rate - last.0) / arr.len() as u64;
                        rx_rate = (rx_rate - last.1) / arr.len() as u64;
                        rates.lock().unwrap().insert(key, (tx_rate, rx_rate));
                    } else {
                        stats.insert(key, ArrayDeque::new());
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    /// Returns rates in a tuple: (tx_rate, rx_rate)
    pub fn get_rates(&self, key: &str) -> (u64, u64) {
        *self.rates.lock().unwrap().get(key).unwrap_or(&(0, 0))
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, thread, time::Duration};

    use async_std::task::block_on;

    use super::*;
    #[test]
    fn resolve() {
        let mut resolver = block_on(Resolver::new());
        println!("Resolver connected");
        resolver.start();

        let test_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        resolver.resolve_ip(test_ip);
        thread::sleep(Duration::from_secs(1));

        let name = resolver.resolve_ip(test_ip);
        assert_eq!(name, "one.one.one.one.");

        let test_ip = IpAddr::V4(Ipv4Addr::new(3, 82, 63, 37));
        resolver.resolve_ip(test_ip);
        thread::sleep(Duration::from_secs(1));

        let name = resolver.resolve_ip(test_ip);
        assert_eq!(name, "ec2-3-82-63-37.compute-1.amazonaws.com.");
    }
}
