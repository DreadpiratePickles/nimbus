# Attack paths

nimbus turns findings and inventory into a security graph, then walks that graph from the internet towards your crown jewels. The scoring copies the most transparent model on the market, Google SCC's attack exposure score, and the whole formula is published here.

## The score

```text
score       = likelihood × priority                  (0–10)
likelihood  = Π step_exploitability × hop_decay^hops  (AND along a path, OR across paths)
priority    = crown-jewel criticality: tier 4 → 10, 3 → 5, 2 → 2, 1 → 1
```

Defaults: up to **6 hops**, `hop_decay = 0.95`, at most 500 paths, and paths below a score of 0.5 are dropped. The code is in [`internal/attackpath/traversal.go`](https://github.com/DreadpiratePickles/nimbus/blob/main/internal/attackpath/traversal.go).

### Step exploitability

Every edge in a path has a weight, and the weight depends on the weakness that makes the step possible. A sample:

| Step | Weakness | Exploitability |
|---|---|---|
| internet → data store | `PUBLIC_DATA_STORE` | 1.0 |
| internet → workload | public **and** unpatched / CVEs | 0.95 |
| internet → workload | public **and** weak auth | 0.8 |
| internet → workload | public only | 0.7 |
| workload → role | `IMDSV1_ENABLED` (SSRF credential theft) | 0.9 |
| container → node identity | `PRIVILEGED_CONTAINER` / host access | 0.85 |
| identity → policy | wildcard admin policy | 1.0 |
| role → role | cross-account trust | 0.9 |
| binding → cluster | `CLUSTER_ADMIN` | 1.0 |

Each step records the weakness behind it, so a path reads like a story: *reachable from the internet → role credentials stolen via IMDSv1 → admin privileges reach the data*. Paths also carry MITRE ATT&CK tags.

### Crown jewels

A node's tier (0 = not a target, 4 = tier-0) comes from:

1. your `scan.crown_jewels` rules in [the config](configuration.md): a glob on name, id or type → `criticality` 1–4;
2. otherwise its class: a sensitive production data store is 4, a sensitive data store 3, any other data store 2, an over-privileged or cluster-admin identity 4, and a cluster or account 3;
3. a built-in default catalog.

## Break the path

`cloud-posture paths --fixes` (and the dashboard's *Attack paths* tab) analyses every path together:

- **Choke points**: nodes that many paths go through, ranked by path count and then by total score.
- **Break vs lower-risk**: each fix is labelled by what it does. *Breaks the path* means the path disappears. *Lowers risk only* means the path survives with lower likelihood.
- **Cheapest fix set**: a greedy weighted set cover that cuts every path, reported with the share of total path score it removes.
- **Blast radius**: `--blast-radius` lists everything a node can reach and which of those targets are sensitive.

```bash
cloud-posture paths --fixes
cloud-posture paths --format mermaid > paths.mmd
cloud-posture graph export --format cypher     # or: graph push  (Neo4j, Cartography-style labels)
```

You can add your own rule chains with `scan.attack_rules_file`.
