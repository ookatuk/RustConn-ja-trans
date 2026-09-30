---
inclusion: fileMatch
fileMatchPattern: "{rustconn-core/src/models/protocol.rs,rustconn-core/src/*_client/config.rs,rustconn-core/src/protocol/freerdp.rs,rustconn/src/window/protocols.rs,rustconn/src/window/rdp_vnc.rs,rustconn/src/embedded_rdp/launcher.rs,rustconn-core/src/export/*.rs,rustconn-core/src/import/*.rs}"
---

# Config-Mapping Fidelity — Development Rules

You are editing a persisted config, a runtime/client config, a launch mapper, or
an import/export converter. These are the files where a field can be *stored but
never used*, or *written but never read back*. The 0.22.12 audit found three such
bugs here that compiled cleanly and passed clippy — the compiler does not check
this class, so you must.

## The core fact

The **persisted** config and the **runtime/client** config are two independent
structs, kept in sync by a **hand-written mapper**. There is no derive, no
`From`, nothing that fails to build when a field is added on one side and not the
other. Examples of the split:

| Persisted (saved to disk) | Runtime/client | Mapper (the only link) |
|---|---|---|
| `models::protocol::SpiceConfig` | `spice_client::SpiceClientConfig` | `rustconn/src/window/protocols.rs` |
| `models::protocol::RdpConfig` | `rdp_client::RdpClientConfig` / `protocol::FreeRdpConfig` | `window/rdp_vnc.rs`, `embedded_rdp/launcher.rs` |

## Three rules, every time you touch these files

1. **A new persisted field MUST get a consumer in the mapper.** If you add a
   field to `SpiceConfig`/`RdpConfig`/etc., add the line in the mapper
   (`window/protocols.rs` for SPICE, `window/rdp_vnc.rs` / `embedded_rdp/launcher.rs`
   for RDP) that reads it into the client config or a launch arg. A field that
   exists only in the struct, its `Default`, its `PartialEq` and serde derives is
   a **dead field**. That is exactly how SPICE `proxy` and `shared_folders`
   shipped doing nothing — the editor stored them, the mapper dropped them.

2. **A UI handle either reaches an effect or says it does not.** A `SwitchRow` /
   `EntryRow` in `dialogs/connection/` must trace to a config field that IS
   consumed, or a CLI arg. If it dead-ends, mark it in the subtitle/tooltip as
   "reserved / not yet implemented" — do not ship a switch that silently does
   nothing. (The embedded RDP `smartcard_enabled` / `microphone_enabled` fields
   are the documented reserved case; FIDO2, by contrast, is genuinely wired for
   the external FreeRDP client via `/fido`.)

3. **An exporter value must round-trip.** Anything an exporter writes (e.g. an
   Ásbrú `method:`) must have a branch in the matching importer that reads it
   back — or the protocol must be in an explicit skip list with a warning. Ásbrú
   export wrote `method: "SPICE"` / `"serial"` that neither Ásbrú-CM nor our own
   importer understood; the fix was to skip unsupported protocols and honestly
   report `supports_protocol`.

## If you cannot wire it now

That is fine — but be explicit. Document the field as reserved (rule 2 style),
leave a `// TODO(<what is missing>)` at the mapper site, and note it in the PR /
CHANGELOG. A documented gap is honest; a silent one is a shipped bug.
