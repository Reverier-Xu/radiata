# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Route planning replaces per-hop next-hop selection: a `RouteNextHop`
  policy now plans the ordered path a packet follows, the path rides the
  route envelope, and every hop follows it. The default policy plans the
  success-rate weighted shortest path over a node-local topology graph
  learned from observed route outcomes, falling back to the trace-keyed
  single relay while nothing has been learned.
- `StreamTarget::Path` lets a caller name the ordered path itself;
  admission validates it (shape, hop budget, membership, first-hop
  reachability) and every hop follows it exactly.
- `NextHopView::remaining_hops` exposes the hop budget left to a policy.
- Wire: the routed open frame's route element carries the remaining path
  (a pre-release format amendment); legacy direct frames are unchanged.

[Unreleased]: https://github.com/Reverier-Xu/radiata/commits/main
