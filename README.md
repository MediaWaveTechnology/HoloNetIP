# HoloNetIP

A live 3D map and telemetry view for IP networks.

- **Backend** (`holonet/backend.py`): one persistent, read-only SSH session to a router.
  It reports per-client and WAN up/down rates from byte counters, uses the router's ARP and
  DHCP tables as the device list, and runs scheduled speed tests. It serves `/api/live`,
  `/metrics` (Prometheus) and `/healthz` on 127.0.0.1. GET only.
- **Map** (`map/`): `netmap_agent.py` serves the Three.js page plus `/api/topology` and
  `/api/stream` on 127.0.0.1. It joins router data, nmap discovery and an approved-device
  inventory, and raises alerts for unknown devices. Device-supplied text is escaped.

Everything binds to 127.0.0.1. Nothing in this project writes to the router.

## Router support

| Firmware | Status |
|---|---|
| ASUS stock firmware (tested on RT-BE92U) | Supported |
| ASUS Merlin firmware | Planned as a second adapter |
| Other vendors | Not supported; the adapter fails with an explicit error |

## Try it

The map runs offline on a built-in fixture. Open `map/index.html` in a browser, or run:

    make install
    make validate

## Configuration (never committed)

| File | Purpose |
|---|---|
| `~/.holonet/router.env` | `ROUTER_SSH_USER`, `ROUTER_SSH_HOST`, `ROUTER_SSH_PORT` |
| `~/.holonet/known_hosts` | Pinned router host key |
| `~/.ssh/id_ed25519_holonet_router` | Router key (read-only use) |
| `inventory.json` (your local copy) | Approved devices, keyed by MAC address |

Keep keys, `router.env`, `known_hosts`, real inventories and real MAC lists out of git.
Tests and fixtures use the `02:00:00:…` MAC range and the `192.0.2.0/24` documentation network.

## License

MIT. See [LICENSE](LICENSE).
