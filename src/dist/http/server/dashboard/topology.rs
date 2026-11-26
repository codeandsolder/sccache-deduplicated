//! Project authenticated membership, advertised routes and measured service.
//! The graph is logical: an edge does not assert a physical cable or hop.
use std::{collections::BTreeMap, net::SocketAddr};

use crate::{
    build_runtime::{Direction, NetworkMeter, Peer, PeerId},
    errors::Result,
};
use sccache_cluster_identity::{Role, SchedulerEnrollment};
use sccache_dashboard::{
    HostInterface, HostRole, NetworkHost, NetworkLink, RouteEvidence, Snapshot,
};

use super::super::SchedulerRequester;

fn host(id: String, name: String, role: HostRole, status: &str) -> NetworkHost {
    NetworkHost {
        id,
        name,
        role,
        status: status.into(),
        addresses: Vec::new(),
        interfaces: Vec::new(),
    }
}

const fn member_role(role: Role) -> HostRole {
    match role {
        Role::Scheduler => HostRole::Scheduler,
        Role::Worker => HostRole::Worker,
        Role::Client => HostRole::Client,
    }
}

const fn role_name(role: HostRole) -> &'static str {
    match role {
        HostRole::Scheduler => "Scheduler",
        HostRole::Worker => "Worker",
        HostRole::Client => "Client",
        HostRole::Upstream => "Upstream",
    }
}

fn add_address(host: &mut NetworkHost, address: String) {
    if !host.addresses.contains(&address) {
        host.addresses.push(address);
    }
}

fn link(
    source: String,
    target: String,
    addresses: (Option<String>, Option<String>),
    evidence: RouteEvidence,
) -> NetworkLink {
    let (source_address, target_address) = addresses;
    let id = format!(
        "{source}>{target}|{}|{}",
        source_address.as_deref().unwrap_or("?"),
        target_address.as_deref().unwrap_or("?")
    );
    NetworkLink {
        id,
        source,
        target,
        source_address,
        target_address,
        evidence,
        wire_bytes_per_second: None,
        logical_bytes_per_second: None,
        remaining_bytes: None,
    }
}

struct Graph {
    hosts: BTreeMap<String, NetworkHost>,
    links: BTreeMap<String, NetworkLink>,
}

impl Graph {
    fn observe(&mut self, mut link: NetworkLink) {
        if link.source == link.target
            || !self.hosts.contains_key(&link.source)
            || !self.hosts.contains_key(&link.target)
        {
            return;
        }
        for (id, address) in [
            (&link.source, &link.source_address),
            (&link.target, &link.target_address),
        ] {
            if let (Some(host), Some(address)) = (self.hosts.get_mut(id), address) {
                add_address(host, address.clone());
            }
        }
        if let Some(prior) = self.links.remove(&link.id) {
            link.wire_bytes_per_second = link.wire_bytes_per_second.or(prior.wire_bytes_per_second);
            link.logical_bytes_per_second = link
                .logical_bytes_per_second
                .or(prior.logical_bytes_per_second);
            link.remaining_bytes = link.remaining_bytes.or(prior.remaining_bytes);
            if prior.evidence == RouteEvidence::Transferring {
                link.evidence = prior.evidence;
            }
        }
        self.links.insert(link.id.clone(), link);
    }

    fn meter(&mut self, scheduler: &str, network: &NetworkMeter) {
        let snapshot = network.snapshot();
        for (direction, snapshot) in [
            (Direction::Send, snapshot.send),
            (Direction::Receive, snapshot.receive),
        ] {
            for (peer, capacity) in snapshot.peers {
                if capacity.body_bytes == 0 && capacity.active_remaining_bytes == 0 {
                    continue;
                }
                let path = peer.path();
                let (id, role) = match peer.principal() {
                    Peer::Worker(id) => (id.to_string(), HostRole::Worker),
                    Peer::Client(id) => (id.to_string(), HostRole::Client),
                    Peer::Upstream => (
                        path.map_or_else(
                            || "upstream".into(),
                            |path| format!("upstream:{}", path.remote),
                        ),
                        HostRole::Upstream,
                    ),
                    _ => continue,
                };
                let active = capacity.active_remaining_bytes > 0;
                let node = self.hosts.entry(id.clone()).or_insert_with(|| {
                    host(
                        id.clone(),
                        format!(
                            "{} {}",
                            role_name(role),
                            id.chars().take(12).collect::<String>()
                        ),
                        role,
                        "Previously observed",
                    )
                });
                if active && node.status != "Revoked" {
                    node.status = "Transferring".into();
                }
                let (local, remote) = path.map_or((None, None), |path| {
                    (Some(path.local.to_string()), Some(path.remote.to_string()))
                });
                let (source, target, addresses) = match direction {
                    Direction::Send => (scheduler.to_owned(), id, (local, remote)),
                    Direction::Receive => (id, scheduler.to_owned(), (remote, local)),
                };
                let mut route = link(
                    source,
                    target,
                    addresses,
                    if active {
                        RouteEvidence::Transferring
                    } else {
                        RouteEvidence::Measured
                    },
                );
                let rate = if capacity.observed_bytes_per_second != 0 {
                    capacity.observed_bytes_per_second
                } else {
                    capacity.isolated_bytes_per_second
                };
                route.wire_bytes_per_second = (rate != 0).then_some(rate);
                route.remaining_bytes = Some(capacity.active_remaining_bytes);
                self.observe(route);
            }
        }
    }
}

fn scheduler_host(id: String, address: SocketAddr) -> NetworkHost {
    let mut node = host(id, "Scheduler".into(), HostRole::Scheduler, "Online");
    add_address(&mut node, address.to_string());
    for interface in crate::dist::cluster::interface_report().interfaces {
        let addresses = interface
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        for address in &addresses {
            add_address(&mut node, address.clone());
        }
        node.interfaces.push(HostInterface {
            index: interface.index,
            addresses,
            nominal_bytes_per_second: interface.nominal_capacity,
            tx_bytes_per_second: interface.send.total_bytes_per_second,
            rx_bytes_per_second: interface.receive.total_bytes_per_second,
            external_tx_bytes_per_second: interface.send.external_bytes_per_second,
            external_rx_bytes_per_second: interface.receive.external_bytes_per_second,
        });
    }
    node
}

pub(in crate::dist::http) fn enrich(
    snapshot: &mut Snapshot,
    scheduler: PeerId,
    public_addr: SocketAddr,
    enrollment: &SchedulerEnrollment,
    requester: &SchedulerRequester,
    network: Option<&NetworkMeter>,
) -> Result<()> {
    let mut graph = Graph {
        hosts: snapshot
            .topology
            .hosts
            .drain(..)
            .map(|host| (host.id.clone(), host))
            .collect(),
        links: BTreeMap::new(),
    };
    let scheduler = scheduler.to_string();
    graph.hosts.insert(
        scheduler.clone(),
        scheduler_host(scheduler.clone(), public_addr),
    );
    for (id, role, revoked) in enrollment.authority().registry().members()? {
        let id = id.to_string();
        let role = member_role(role);
        let node = graph.hosts.entry(id.clone()).or_insert_with(|| {
            host(
                id.clone(),
                format!(
                    "{} {}",
                    role_name(role),
                    id.chars().take(12).collect::<String>()
                ),
                role,
                "Enrolled · not recently observed",
            )
        });
        if revoked {
            node.status = "Revoked".into();
        }
    }
    // Only fresh worker registrations advertise contact candidates.
    let routes = requester
        .addresses
        .lock()
        .map_err(|_| anyhow::anyhow!("worker routes poisoned"))?;
    for (id, (routes, updated)) in routes.iter() {
        if updated.elapsed() >= super::super::HEARTBEAT_TIMEOUT {
            continue;
        }
        let id = id.to_string();
        for endpoint in routes.iter() {
            graph.observe(link(
                scheduler.clone(),
                id.clone(),
                (None, Some(endpoint.to_string())),
                RouteEvidence::Advertised,
            ));
        }
    }
    drop(routes);
    for route in snapshot.topology.links.drain(..) {
        graph.observe(route);
    }
    if let Some(network) = network {
        graph.meter(&scheduler, network);
    }
    for host in graph.hosts.values_mut() {
        host.addresses.sort_unstable();
        host.addresses.dedup();
    }
    snapshot.topology.hosts = graph.hosts.into_values().collect();
    snapshot.topology.links = graph.links.into_values().collect();
    Ok(())
}
