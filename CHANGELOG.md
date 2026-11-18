# v0.1.0

First release of Mihomo Route Audit, a read-only tool for checking fixed routes after a configuration change or subscription refresh.

- Compare the running Mihomo rule prefix, TUN setting, process matching and single-node group with a local JSON policy.
- Evaluate a synthetic snapshot offline, or query the running core through an existing user-owned Unix socket.
- Get a JSON result with rule positions and diagnostic codes without printing local policies, proxy names or controller responses.
- Run using Python 3.11+ on macOS or Linux without installing Python packages.

A pass covers the controller state. It does not measure the public exit IP, IPv6, DNS, application traffic or login.
