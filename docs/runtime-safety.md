# Runtime safety & security model

The Runtime Lab is for the operator's own APKs, explicitly authorized test
applications, `AndroidSecForge-TestApp`, and controlled research
devices/emulators. It is analysis instrumentation, not an offensive tool.

## Hard guarantees

- Never executes an APK automatically; never installs, launches, connects, or
  instruments without an explicit user command.
- No exploit generation, no payload generation, no arbitrary command execution
  through the framework, no persistence, privilege escalation, stealth, evasion,
  credential theft, or weaponization.
- Hooks are **observation-only** — they log and return the original result
  unchanged; they never modify return values, bypass checks, disable TLS, inject
  commands, alter authentication, dump credentials, bypass permissions, or patch
  memory.
- No privilege escalation is attempted; `rooted` is only inferred from safely
  observable build properties.
- Sensitive values are masked before persistence; secrets are never stored
  verbatim; long tokens are collapsed.

## Audit trail

Every mutating operation writes a `runtime_audit_events` row: `who`
(`requested_by`), `operation` (`CREATE`/`SELECT_DEVICE`/`INSTALL`/`UNINSTALL`/
`LAUNCH`/`STOP`/`LOGCAT_START`/`LOGCAT_STOP`/`PROCESS`/`FRIDA_ATTACH`/
`FRIDA_DETACH`), device, package, session, timestamp, result, error, and the
actual command.

## Bounds

Per-command timeout, session timeout, logcat byte/line caps, observation-count
cap, and artifact size cap (all `ASF_RUNTIME_*`). No unbounded event stream.

## Offline

If ADB or Frida is unavailable, runtime analysis degrades to honest
`UNAVAILABLE`/`FAILED` and the rest of AndroidSecForge remains fully usable
offline. `runtime doctor` never reports READY for a capability that was detected
but is not actually usable.
