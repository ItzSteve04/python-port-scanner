# TCP service hint maintenance

The versioned mapping is `src/port_scanner/data/services.json`. Version **2026.10** was reviewed
on **2026-10-24**. It is a curated set of common conventions, not a copy of the full IANA registry.

Lookup order:

1. Project mapping → `service_source: curated`.
2. Local OS services database via `socket.getservbyport(port, "tcp")` → `system`.
3. No match → `unknown`.

Registered service names are based on the [IANA registry](https://www.iana.org/assignments/service-names-port-numbers/).
For readability, several labels are familiar deployment aliases rather than exact IANA names:

| Port | Project hint | Interpretation |
| --- | --- | --- |
| 135 | `msrpc` | Familiar name for Microsoft's endpoint-mapper deployment |
| 1521 | `oracle-tns` | Common Oracle listener convention |
| 2375, 2376 | `docker-api`, `docker-api-tls` | Common Docker API conventions |
| 8000 | `http-alt (common)` | HTTP is common here; this is not its IANA assignment |
| 8443 | `https-alt (common)` | HTTPS is common here; this is not its IANA assignment |
| 9200 | `elasticsearch (common)` | Elasticsearch commonly uses this port |

The mapping intentionally never turns a port number into a confirmed product or version.
No automatic live refresh occurs during scanning. OS fallback names depend on the platform
and on its services database updates.

When maintaining this file, review conventions against IANA and relevant vendor documentation,
keep aliases explicit, update `version` and `reviewed_on`, and run the tests ensuring all common
ports have curated hints. Include sources in the change description. Review when preparing a
release, or when a reported mapping issue warrants it. A review date is not a promise of a
scheduled future update.
