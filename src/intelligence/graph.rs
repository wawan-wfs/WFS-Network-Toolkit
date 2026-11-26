//! Read-only graph. Shared node identity is explicit and restricted to one router.
use super::visual::{Edge, MAX_EDGES};
use std::collections::{BTreeMap, VecDeque};

pub const COLUMN_WIDTH: i32 = 236;
pub const ROW_HEIGHT: i32 = 72;
pub const NODE_WIDTH: i32 = 204;
pub const NODE_HEIGHT: i32 = 54;
const COLUMNS: usize = 4;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    router: String,
    kind: &'static str,
    name: String,
    isolation: String,
}

#[derive(Clone, Debug)]
pub struct Node {
    pub name: String,
    pub kind: &'static str,
    pub authority: String,
    pub scope: String,
    pub x: i32,
    pub y: i32,
    pub incident: Vec<usize>,
}

#[derive(Clone, Copy, Debug)]
pub struct Link {
    pub from: usize,
    pub to: usize,
    pub evidence: usize,
}

/// Vertical connected-component index. All links lie entirely inside their
/// own component band, so skipping an offscreen band cannot hide a crossing.
#[derive(Debug)]
pub struct Band {
    pub top: i32,
    pub bottom: i32,
    pub nodes: Vec<usize>,
    pub links: Vec<usize>,
}

#[derive(Default)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
    pub limited: bool,
    pub height: i32,
    pub components: usize,
    bands: Vec<Band>,
}

fn column(kind: &str) -> usize {
    match kind {
        "VRF" | "Bridge" | "Tabel rute" => 0,
        "VLAN" | "Rute default" | "Bridge / VLAN" => 1,
        "Interface" | "Daftar interface" => 2,
        _ => 3,
    }
}

fn key(edge: &Edge, left: bool, index: usize) -> Key {
    let (kind, name) = if left {
        (edge.left_kind, &edge.left)
    } else {
        (edge.right_kind, &edge.right)
    };
    // Router-scoped interface/bridge/VLAN labels are names, not a physical ID.
    // FDB, neighbor, routes, lists and missing authorities must remain isolated.
    let router = edge.authority.clone().unwrap_or_default();
    let isolation = if router.is_empty() || !matches!(kind, "Interface" | "Bridge" | "VLAN" | "VRF")
    {
        format!("{index}:{}:{}", u8::from(left), edge.scope)
    } else if matches!(kind, "Interface") {
        // Preserve exact VRF/interface evidence scope; don't join ambiguous aliases.
        edge.scope.clone()
    } else {
        String::new()
    };
    Key {
        router,
        kind,
        name: name.clone(),
        isolation,
    }
}

impl Graph {
    pub fn build(edges: &[Edge]) -> Self {
        let mut graph = Self {
            limited: edges.len() > MAX_EDGES,
            ..Default::default()
        };
        let mut ids = BTreeMap::new();
        for (index, edge) in edges.iter().take(MAX_EDGES).enumerate() {
            let mut pair = [0; 2];
            for (side, node_id) in pair.iter_mut().enumerate() {
                let k = key(edge, side == 0, index);
                let id = *ids.entry(k.clone()).or_insert_with(|| {
                    let id = graph.nodes.len();
                    graph.nodes.push(Node {
                        name: k.name,
                        kind: k.kind,
                        authority: k.router,
                        scope: edge.scope.clone(),
                        x: 0,
                        y: 0,
                        incident: Vec::new(),
                    });
                    id
                });
                graph.nodes[id].incident.push(index);
                *node_id = id;
            }
            graph.links.push(Link {
                from: pair[0],
                to: pair[1],
                evidence: index,
            });
        }
        graph.layout_components();
        graph
    }

    // Lay out disconnected evidence components in distinct vertical bands.
    // IDs and evidence order remain stable for legacy selection and drilldown.
    fn layout_components(&mut self) {
        let mut visited = vec![false; self.nodes.len()];
        let mut top = 0;
        for root in 0..self.nodes.len() {
            if visited[root] {
                continue;
            }
            self.components += 1;
            visited[root] = true;
            let mut pending = VecDeque::from([root]);
            let mut members = Vec::new();
            while let Some(id) = pending.pop_front() {
                members.push(id);
                for &edge in &self.nodes[id].incident {
                    let link = self.links[edge];
                    let other = if link.from == id { link.to } else { link.from };
                    if !visited[other] {
                        visited[other] = true;
                        pending.push_back(other);
                    }
                }
            }
            members.sort_unstable();
            let mut counts = [0i32; COLUMNS];
            let mut band_links = Vec::new();
            for &id in &members {
                let node = &mut self.nodes[id];
                let col = column(node.kind);
                node.x = col as i32 * COLUMN_WIDTH;
                node.y = top + counts[col] * ROW_HEIGHT;
                counts[col] += 1;
                self.height = self.height.max(node.y + NODE_HEIGHT);
                band_links.extend_from_slice(&node.incident);
            }
            let bottom = top + (counts.into_iter().max().unwrap_or(1) - 1) * ROW_HEIGHT + NODE_HEIGHT;
            band_links.sort_unstable();
            band_links.dedup();
            self.bands.push(Band { top, bottom, nodes: members, links: band_links });
            top = bottom + (ROW_HEIGHT - NODE_HEIGHT) + 24;
        }
    }

    /// Binary search the visible vertical band interval; no per-frame scan
    /// of disconnected components. The caller still clips individual edges.
    pub fn visible_bands(&self, viewport: Viewport, top: i32, bottom: i32) -> &[Band] {
        if bottom < top {
            return &[];
        }
        let first = self.bands.partition_point(|band| viewport.project(0, band.bottom).1 < top);
        let end = self.bands.partition_point(|band| viewport.project(0, band.top).1 <= bottom);
        &self.bands[first..end.max(first)]
    }

    pub fn width(&self) -> i32 {
        COLUMNS as i32 * COLUMN_WIDTH
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Viewport {
    pub pan_x: i32,
    pub pan_y: i32,
    pub scale: i32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            pan_x: 0,
            pan_y: 0,
            scale: 100,
        }
    }
}

impl Viewport {
    pub fn project(self, x: i32, y: i32) -> (i32, i32) {
        (
            self.pan_x + x * self.scale / 100,
            self.pan_y + y * self.scale / 100,
        )
    }

    pub fn pan(&mut self, dx: i32, dy: i32) {
        self.pan_x = self.pan_x.saturating_add(dx).clamp(-240_000, 1_000);
        self.pan_y = self.pan_y.saturating_add(dy).clamp(-240_000, 1_000);
    }

    pub fn zoom(&mut self, scale: i32) {
        self.scale = scale.clamp(40, 200);
    }

    pub fn hit(self, graph: &Graph, x: i32, y: i32) -> Option<usize> {
        graph.visible_bands(self, y, y).iter().rev()
            .flat_map(|band| band.nodes.iter().rev())
            .find_map(|&id| {
                let node = &graph.nodes[id];
                let (left, top) = self.project(node.x, node.y);
                let (right, bottom) = self.project(node.x + NODE_WIDTH, node.y + NODE_HEIGHT);
                (x >= left && x < right && y >= top && y < bottom).then_some(id)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::{network_map::Observation, router::Table};

    fn edge(router: &str, name: &str, port: &str, scope: &str) -> Edge {
        Edge::scoped(
            router,
            &Observation {
                subject: name.into(),
                target: port.into(),
                scope: scope.into(),
                basis: "Relasi eksplisit",
                source: Table::BridgePorts.name(),
                observed_at: 42,
                details: "fixture".into(),
            },
        )
    }

    #[test]
    fn merges_bridge_nodes_but_never_distinct_router_or_port_scope() {
        let graph = Graph::build(&[
            edge("r1", "br", "ether1", "blue"),
            edge("r1", "br", "ether2", "blue"),
            edge("r2", "br", "ether1", "blue"),
            edge("r1", "br", "ether1", "red"),
        ]);
        assert_eq!(graph.nodes.len(), 6);
        assert_eq!(graph.links.len(), 4);
        assert_eq!(graph.links[0].from, graph.links[1].from);
        assert_ne!(graph.links[0].from, graph.links[2].from);
        assert_ne!(graph.links[0].to, graph.links[3].to);
        assert_eq!(graph.nodes[graph.links[0].from].incident, vec![0, 1, 3]);
    }

    #[test]
    fn separate_components_are_banded_and_selection_is_stable() {
        let graph = Graph::build(&[
            edge("r1", "br1", "ether1", "blue"),
            edge("r2", "br1", "ether1", "blue"),
            edge("r1", "br1", "ether2", "blue"),
        ]);
        assert_eq!(graph.components, 2);
        assert_eq!(graph.links[2].evidence, 2);
        assert_eq!(graph.links[0].from, graph.links[2].from);
        assert!(graph.nodes[graph.links[1].from].y > graph.nodes[graph.links[2].to].y);
        assert_eq!(Graph::build(&[]).components, 0);
    }

    #[test]
    fn band_index_matches_brute_force_and_never_drops_crossing_links() {
        let edges: Vec<_> = (0..MAX_EDGES).map(|i| edge(&format!("r{i}"), "br", "ether1", "blue")).collect();
        let graph = Graph::build(&edges);
        assert_eq!(graph.components, MAX_EDGES);
        let mut viewport = Viewport::default();
        for scale in [40, 100, 200] {
            viewport.zoom(scale);
            for pan in [0, -600, -15000, -40000] {
                viewport.pan_y = pan;
                let bands = graph.visible_bands(viewport, 0, 480);
                let expected: Vec<_> = graph.bands.iter().filter(|band| {
                    viewport.project(0, band.bottom).1 >= 0 && viewport.project(0, band.top).1 <= 480
                }).map(|b| b.top).collect();
                assert_eq!(bands.iter().map(|b| b.top).collect::<Vec<_>>(), expected);
                assert!(bands.len() < 20);
                for band in bands {
                    for &link in &band.links {
                        assert!(band.nodes.contains(&graph.links[link].from));
                        assert!(band.nodes.contains(&graph.links[link].to));
                    }
                }
            }
        }
        assert!(graph.visible_bands(viewport, 10, 0).is_empty());
    }

    #[test]
    fn bounded_hit_and_pan() {
        let edges = vec![edge("r1", "br", "ether1", "blue"); MAX_EDGES + 5];
        let graph = Graph::build(&edges);
        assert!(graph.limited);
        assert_eq!(graph.links.len(), MAX_EDGES);
        let mut viewport = Viewport::default();
        viewport.pan(30, 40);
        viewport.zoom(999);
        let node = &graph.nodes[0];
        let (x, y) = viewport.project(node.x, node.y);
        assert_eq!(viewport.hit(&graph, x + 1, y + 1), Some(0));
        assert!(viewport.hit(&graph, -999, -999).is_none());
        viewport.pan(i32::MIN, i32::MAX);
        assert_eq!(viewport.pan_x, -240_000);
        assert_eq!(viewport.pan_y, 1_000);
    }
}
