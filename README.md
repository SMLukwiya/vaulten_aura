# Vaulten-Aura Runtime

**A self-hosted, high performance, edge-native runtime built for immutability, security, and control.**

Vaulten aura is an open-source edge runtime built from scratch in C.
It is designed for operators and teams who want deep control over how functions
are deployed, executed, and secured — without relying on opaque managed platforms.

> **Status:** alpha1  
> Exploratory, incomplete, and intentionally transparent, buggy as hell.

---

## Why Vaulten Aura?

Modern edge platforms are powerful, but they hide critical decisions behind
managed control planes and generic servers.

Vaulten aura takes a different approach:

- Build close to the kernel
- Make performance trade-offs explicit
- Treat immutability as a first-class concept
- Give operators real control

This project exists to explore what an edge runtime looks like
when **security, cold-start performance, and correctness** are not abstractions,
but design constraints.

---

## What works today (alpha1)

### Server & networking
- Custom edge-native server written in C
- HTTP/2 only
- TLS 1.3 using picotls and minSSL
- Pure epoll-based event loop
- Explicit control over:
- epoll wait strategy
- request intake per tick
- prioritization of short-lived requests

### Control plane
- CLI to:
- start/stop the daemon
- start/stop the server
- check server status
- deploy functions
- Daemon coordinating CLI and server
- YAML-based configuration for server and functions

### Configuration & deployment
- Event-driven, streaming YAML parser
- Early termination for large configs
- Deep validation with precise line/column error reporting
- Custom binary blob format:
- combines function config and code
- optimized for fast parsing
- O(1) access to sections via precomputed tables

### Routing & execution
- Radix tree for deployed and active routes
- Explicit separation between deploy and activate
- Verified function invocation via nghttp2

---

## What “edge-native” means in Vaulten Aura

- Cold-start performance is a first-class concern
- Short-lived requests are prioritized explicitly
- No hidden control plane
- No implicit lifecycle transitions
- Immutable artifacts by design
- Built close to the kernel, not layered on top of generic servers
- Regional and global function control

---

## Version 1 goals

Version 1 focuses on being a complete, honest, self-hosted edge runtime.

### Planned for v1
- Daemon configuration isolated from server configuration
- Daemon key generation and secure storage
- Lightweight CLI authentication
- Encryption of function artifacts and configs at rest
- Load-aware epoll wait tuning
- JavaScript execution via QuickJS
- Support for:
  - fetch
  - timers
  - logging
- Explicit function lifecycle management

### Explicitly out of scope for v1
- WASM support (planned for later)
- HTTP/1.x compatibility
- Managed SaaS control plane
- Opaque autoscaling or hidden scheduling logic
- Automatic function rollbacks based on predefined success matrix

---

## Project philosophy

Vaulten Aura favors:
- Explicit over implicit
- Control over convenience
- Transparency over abstraction
- Correctness over generality

## Design Principles
1. Explicit over Implicit
2. Immutable artifacts
3. Edge-first orchestration
4. Performance is measurable
5. Simple abstraction
6. Transparency over convenience
7. Operator control
8. Incremental correctness

If something is slow, unsafe, or complex — it should be visible.

---

## Looking for feedback

Vaulten aura is an early, opinionated system.

If you’ve built:
- servers
- runtimes
- CDNs
- edge platforms
- or low-level infrastructure

your feedback is especially welcome.

Discussions, and architectural critique are encouraged.
Issues are still not welcome as the code still needs some organisation and tidiness inorder
not to waste people's valuable time.

---

## License
This project is licensed under the GNU Affero General Public License v3 (AGPLv3)

If you use this software over a network, modifications must be made under the same license.
Copyright (c) 2025 SMLukwiya