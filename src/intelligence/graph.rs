//! Read-only graph. Shared node identity is explicit and restricted to one router.
use super::visual::{Edge, MAX_EDGES};
use std::collections::BTreeMap;

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

#[derive(Default)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
    pub limited: bool,
    pub height: i32,
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
    let isolation = if router.is_empty()
        || !matches!(kind, "Interface" | "Bridge" | "VLAN" | "VRF")
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
        let mut counts = [0i32; COLUMNS];
        for (index, edge) in edges.iter().take(MAX_EDGES).enumerate() {
            let mut pair = [0; 2];
            for (side, node_id) in pair.iter_mut().enumerate() {
                let k = key(edge, side == 0, index);
                let id = *ids.entry(k.clone()).or_insert_with(|| {
                    let c = column(k.kind);
                    let y = counts[c] * ROW_HEIGHT;
                    counts[c] += 1;
                    graph.height = graph.height.max(y + NODE_HEIGHT);
                    let id = graph.nodes.len();
                    graph.nodes.push(Node {
                        name: k.name,
                        kind: k.kind,
                        authority: k.router,
                        scope: edge.scope.clone(),
                        x: c as i32 * COLUMN_WIDTH,
                        y,
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
        graph
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
        graph.nodes.iter().enumerate().rev().find_map(|(id, node)| {
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
        Edge::scoped(router, &Observation {
            subject: name.into(),
            target: port.into(),
            scope: scope.into(),
            basis: "Relasi eksplisit",
            source: Table::BridgePorts.name(),
            observed_at: 42,
            details: "fixture".into(),
        })
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
