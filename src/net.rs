use async_std::task::spawn;
use async_std_resolver::{proto::rr::Name, resolver_from_system_conf, AsyncStdResolver};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{mpsc, Arc, Mutex},
};

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
