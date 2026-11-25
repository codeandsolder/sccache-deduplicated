//! Deterministic, keyed SVG layout. Only roster changes move nodes; live
//! route and traffic updates use the native SSE revision stream.
use std::collections::BTreeMap;

use leptos::prelude::*;

use super::rate;
use crate::{HostRole, NetworkGraph, NetworkHost, NetworkLink, RouteEvidence, styles};

#[derive(Clone, Copy, PartialEq, Eq)]
struct Point {
    x: i32,
    y: i32,
}

#[derive(Clone, Default, PartialEq, Eq)]
struct Layout {
    points: BTreeMap<String, Point>,
    height: i32,
}

fn layout(hosts: &[(String, HostRole)]) -> Layout {
    let mut columns: [Vec<&str>; 3] = std::array::from_fn(|_| Vec::new());
    for (id, role) in hosts {
        let column = match role {
            HostRole::Worker => 0,
            HostRole::Scheduler | HostRole::Upstream => 1,
            HostRole::Client => 2,
        };
        columns[column].push(id);
    }
    let rows = columns.iter().map(Vec::len).max().unwrap_or(0);
    let height = i32::try_from(rows)
        .unwrap_or(i32::MAX / 72)
        .saturating_mul(72)
        .saturating_add(40)
        .max(260);
    let mut points = BTreeMap::new();
    for (column, ids) in columns.iter_mut().enumerate() {
        ids.sort_unstable();
        let count = i32::try_from(ids.len()).unwrap_or(i32::MAX / 72);
        for (row, id) in ids.iter().enumerate() {
            let y = (height - count.saturating_mul(72)) / 2
                + i32::try_from(row).unwrap_or(0).saturating_mul(72)
                + 36;
            points.insert(
                (*id).to_owned(),
                Point {
                    x: [158, 480, 802][column],
                    y,
                },
            );
        }
    }
    Layout { points, height }
}

fn role(role: HostRole) -> &'static str {
    match role {
        HostRole::Scheduler => "Scheduler",
        HostRole::Worker => "Worker",
        HostRole::Client => "Client",
        HostRole::Upstream => "Upstream",
    }
}

fn short(text: &str, limit: usize) -> String {
    let mut chars = text.chars();
    let head = chars.by_ref().take(limit).collect::<String>();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

fn optional_rate(value: Option<u64>) -> String {
    value.map_or_else(|| "—".into(), rate)
}

fn evidence(value: RouteEvidence) -> &'static str {
    match value {
        RouteEvidence::Advertised => "Advertised · not measured",
        RouteEvidence::Measured => "Measured / observed",
        RouteEvidence::Transferring => "Transferring",
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct Connection {
    count: usize,
    active: bool,
    measured: bool,
}

type Pair = (String, String);

fn connections(links: &[NetworkLink]) -> BTreeMap<Pair, Connection> {
    let mut groups = BTreeMap::<Pair, Connection>::new();
    for link in links {
        let group = groups
            .entry((link.source.clone(), link.target.clone()))
            .or_default();
        group.count += 1;
        group.active |= link.evidence == RouteEvidence::Transferring;
        group.measured |= link.evidence != RouteEvidence::Advertised;
    }
    groups
}

#[component]
pub(super) fn Topology(graph: Memo<NetworkGraph>) -> impl IntoView {
    let selected = RwSignal::new(String::new());
    let hosts = Memo::new(move |_| {
        graph.with(|graph| {
            graph
                .hosts
                .iter()
                .map(|host| (host.id.clone(), host.clone()))
                .collect::<BTreeMap<_, _>>()
        })
    });
    let roster = Memo::new(move |_| {
        hosts.with(|hosts| {
            hosts
                .values()
                .map(|host| (host.id.clone(), host.role))
                .collect::<Vec<_>>()
        })
    });
    let positions = Memo::new(move |_| roster.with(|roster| layout(roster)));
    let pairs = Memo::new(move |_| graph.with(|graph| connections(&graph.links)));
    let pair_keys =
        Memo::new(move |_| pairs.with(|pairs| pairs.keys().cloned().collect::<Vec<_>>()));
    let ids = Memo::new(move |_| {
        roster.with(|roster| roster.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>())
    });
    let selected_host =
        Memo::new(move |_| selected.with(|id| hosts.with(|hosts| hosts.get(id).cloned())));
    let links = Memo::new(move |_| {
        graph.with(|graph| {
            let selected = selected.get();
            graph
                .links
                .iter()
                .filter(|link| {
                    selected.is_empty() || link.source == selected || link.target == selected
                })
                .cloned()
                .collect::<Vec<_>>()
        })
    });
    view! {
        <section id="topology">
            <h2>"Network topology"</h2>
            <p class=styles::muted>"Authenticated cluster members and observed transport paths. Lines are logical routes, not physical cables or inferred router hops. Directional arrows represent data flow; dashed lines are advertised candidates only."</p>
            <div class=styles::controls>
                <label>"Inspect host"
                    <select prop:value=move || selected.get() on:change=move |event| selected.set(event_target_value(&event))>
                        <option value="">"All hosts"</option>
                        <For each=move || ids.get() key=Clone::clone children=move |id| {
                            let key = id.clone();
                            view!{<option value=id>{move || hosts.with(|hosts| hosts.get(&key).map_or_else(|| key.clone(), |host| format!("{} · {}",host.name,role(host.role))))}</option>}
                        }/>
                    </select>
                </label>
                <button on:click=move |_| selected.set(String::new())>"Show all"</button>
                <span class=styles::muted>{move || graph.with(|graph| format!("{} identities · {} directional paths",graph.hosts.len(),graph.links.len()))}</span>
            </div>
            <div class=styles::topology_scroll>
                <svg class=styles::topology_svg role="img" aria-label="Directed logical network graph" viewBox=move || format!("0 0 960 {}", positions.with(|p| p.height)) style:height=move || format!("{}px",positions.with(|p| p.height))>
                    <defs><marker id="topology-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke"/></marker></defs>
                    <For each=move || pair_keys.get() key=Clone::clone children=move |pair: Pair| {
                        let geometry = Memo::new({let pair=pair.clone();move |_| positions.with(|layout| layout.points.get(&pair.0).copied().zip(layout.points.get(&pair.1).copied()))});
                        let state = Memo::new({let pair=pair.clone();move |_| pairs.with(|pairs| pairs.get(&pair).cloned().unwrap_or_default())});
                        let pair_select=pair.clone();
                        let highlighted=move || selected.with(|id| id.is_empty() || *id==pair_select.0 || *id==pair_select.1);
                        view!{
                            <path class=move || if state.with(|s|s.active) {styles::topology_active} else if state.with(|s|s.measured) {styles::topology_measured} else {styles::topology_advertised}
                                opacity=move || if highlighted() {"1"} else {"0.12"}
                                d=move || geometry.with(|points| points.map_or_else(String::new, |(a,b)| edge_path(a,b)))
                                marker-end="url(#topology-arrow)">
                                <title>{move || state.with(|s|format!("{} directional route(s){}",s.count,if s.active {" · transferring"} else {""}))}</title>
                            </path>
                        }
                    }/>
                    <For each=move || ids.get() key=Clone::clone children=move |id| {
                        let host = Memo::new({let id=id.clone();move |_| hosts.with(|hosts|hosts.get(&id).cloned())});
                        let position = Memo::new({let id=id.clone();move |_| positions.with(|p|p.points.get(&id).copied())});
                        let node_id=id.clone();
                        let click_id=id.clone();
                        view!{
                            <g class=styles::topology_node transform=move ||position.with(|p|p.map_or_else(String::new,|p|format!("translate({},{})",p.x,p.y)))
                                opacity=move ||selected.with(|id| if id.is_empty() || id==&node_id {"1"} else {"0.48"})
                                on:click=move |_|selected.set(click_id.clone())>
                                <rect x="-128" y="-25" width="256" height="50" rx="7"/>
                                <text y="-4" text-anchor="middle">{move ||host.with(|h|h.as_ref().map_or_else(String::new,|h|short(&h.name,32)))}</text>
                                <text y="13" text-anchor="middle" class=styles::topology_caption>{move ||host.with(|h|h.as_ref().map_or_else(String::new,|h|format!("{} · {}",role(h.role),short(&h.status,29))))}</text>
                                <title>{move ||host.with(|h|h.as_ref().map_or_else(String::new,|h|format!("{}\n{}\n{}",h.name,h.id,h.addresses.join("\n"))))}</title>
                            </g>
                        }
                    }/>
                </svg>
            </div>
            {move || selected_host.get().map(|host|view!{<HostDetails host=host/>})}
            <h3>"Directional routes"</h3>
            <div class=styles::tablewrap><table><thead><tr><th>"Source"</th><th>"Destination"</th><th>"Evidence"</th><th>"Wire service"</th><th>"Logical service"</th><th>"Outstanding"</th></tr></thead>
                <tbody>{move || links.with(|links|links.iter().map(|link| {
                    let name=|id:&str|hosts.with(|hosts|hosts.get(id).map_or_else(||short(id,16),|host|host.name.clone()));
                    view!{<tr><td><b>{name(&link.source)}</b><small>{link.source_address.clone().unwrap_or_else(||"Unknown source".into())}</small></td>
                    <td><b>{name(&link.target)}</b><small>{link.target_address.clone().unwrap_or_else(||"Unknown endpoint".into())}</small></td>
                    <td>{evidence(link.evidence)}</td><td>{optional_rate(link.wire_bytes_per_second)}</td><td>{optional_rate(link.logical_bytes_per_second)}</td>
                    <td>{link.remaining_bytes.map_or_else(||"—".into(),super::bytes)}</td></tr>}
                }).collect_view())}</tbody>
            </table></div>
        </section>
    }
}

fn edge_path(a: Point, b: Point) -> String {
    // Opposite directions bow in opposite ways; terminate at the node boundary.
    if a.x == b.x {
        let sign = if b.y > a.y { 1 } else { -1 };
        return format!(
            "M {} {} C {} {}, {} {}, {} {}",
            a.x + 128,
            a.y,
            a.x + 176,
            a.y + sign * 24,
            b.x + 176,
            b.y - sign * 24,
            b.x + 128,
            b.y
        );
    }
    let sign = if b.x > a.x { 1 } else { -1 };
    let start = a.x + 128 * sign;
    let end = b.x - 128 * sign;
    let middle = (start + end) / 2;
    let bend = 12 * sign;
    format!(
        "M {start} {} C {middle} {}, {middle} {}, {end} {}",
        a.y + bend,
        a.y + bend,
        b.y + bend,
        b.y + bend
    )
}

#[component]
fn HostDetails(host: NetworkHost) -> impl IntoView {
    view! {
        <article class=styles::topology_details><h3>{host.name}</h3><p class=styles::muted>{format!("{} · {} · {}",role(host.role),host.status,host.id)}</p>
            <p>{if host.addresses.is_empty() {"No addresses observed".into()} else {host.addresses.join(" · ")}}</p>
            <div class=styles::tablewrap><table><thead><tr><th>"Interface / addresses"</th><th>"Nominal wired capacity"</th><th>"TX / RX total"</th><th>"TX / RX external"</th></tr></thead><tbody>
                {host.interfaces.into_iter().map(|interface|view!{
                    <tr><td><b>{format!("#{}",interface.index)}</b><small>{interface.addresses.join(" · ")}</small></td><td>{optional_rate(interface.nominal_bytes_per_second)}</td>
                        <td>{format!("{} / {}",rate(interface.tx_bytes_per_second),rate(interface.rx_bytes_per_second))}</td>
                        <td>{format!("{} / {}",rate(interface.external_tx_bytes_per_second),rate(interface.external_rx_bytes_per_second))}</td></tr>
                }).collect_view()}
            </tbody></table></div>
        </article>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn layout_is_stable_for_reordered_roster() {
        let mut roster = vec![
            ("b".into(), HostRole::Worker),
            ("a".into(), HostRole::Worker),
            ("s".into(), HostRole::Scheduler),
            ("c".into(), HostRole::Client),
        ];
        let original = layout(&roster);
        roster.reverse();
        assert_eq!(original.points, layout(&roster).points);
        assert_eq!(original.points.len(), 4);
        assert!(original.points["a"].y < original.points["b"].y);
    }
}
