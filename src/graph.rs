use petgraph::{algo::kosaraju_scc, graph::DiGraph};
use std::collections::{BTreeMap, HashMap};

/// Strongly connected components collapse recursion. Rank zero contains leaves.
pub fn dependency_ranks(ids: &[String], edges: &[(String, String)]) -> HashMap<String, usize> {
    let mut graph = DiGraph::<&str, ()>::new();
    let nodes: HashMap<_, _> = ids
        .iter()
        .map(|id| (id.as_str(), graph.add_node(id.as_str())))
        .collect();
    for (a, b) in edges {
        if let (Some(&a), Some(&b)) = (nodes.get(a.as_str()), nodes.get(b.as_str())) {
            graph.add_edge(a, b, ());
        }
    }
    let components = kosaraju_scc(&graph);
    let mut rank = HashMap::new();
    // kosaraju_scc returns reverse topological order: callees before callers.
    for component in components {
        let depth = component
            .iter()
            .flat_map(|n| graph.neighbors(*n))
            .filter_map(|n| rank.get(graph[n]).copied())
            .max()
            .map_or(0, |r: usize| r + 1);
        for n in component {
            rank.insert(graph[n].to_owned(), depth);
        }
    }
    rank
}

/// Deterministic bounded label propagation groups densely connected neighborhoods.
pub fn modules(ids: &[String], edges: &[(String, String)]) -> HashMap<String, String> {
    let mut neighbors: HashMap<&str, Vec<&str>> =
        ids.iter().map(|id| (id.as_str(), Vec::new())).collect();
    for (a, b) in edges {
        if a == b {
            continue;
        }
        if neighbors.contains_key(a.as_str()) && neighbors.contains_key(b.as_str()) {
            neighbors.get_mut(a.as_str()).unwrap().push(b);
            neighbors.get_mut(b.as_str()).unwrap().push(a);
        }
    }
    let mut labels: HashMap<&str, &str> = ids.iter().map(|s| (s.as_str(), s.as_str())).collect();
    for _ in 0..12 {
        let mut changed = false;
        for id in ids {
            let mut counts = BTreeMap::<&str, usize>::new();
            for neighbor in &neighbors[id.as_str()] {
                *counts.entry(labels[neighbor]).or_default() += 1;
            }
            if let Some((&label, _)) = counts
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
                && label != labels[id.as_str()]
            {
                labels.insert(id, label);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let unique: std::collections::BTreeSet<_> = labels.values().copied().collect();
    let names: HashMap<_, _> = unique
        .into_iter()
        .enumerate()
        .map(|(i, label)| (label, format!("module_{:04}", i + 1)))
        .collect();
    labels
        .into_iter()
        .map(|(id, label)| (id.to_owned(), names[label].clone()))
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recursive_components_share_rank_and_leaves_precede_callers() {
        let ids = ["a", "b", "leaf", "root", "isolated"].map(str::to_owned);
        let edges = [("a", "b"), ("b", "a"), ("b", "leaf"), ("root", "a")]
            .map(|(a, b)| (a.into(), b.into()));
        let rank = dependency_ranks(&ids, &edges);
        assert_eq!(rank["a"], rank["b"]);
        assert!(rank["a"] > rank["leaf"]);
        assert!(rank["root"] > rank["a"]);
        assert_eq!(rank["isolated"], 0);
    }
}
