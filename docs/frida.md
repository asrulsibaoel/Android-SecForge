# Frida adapter

`backend/app/runtime/frida.py` is an **optional, observation-only** instrumentation
adapter.

## Detection

`runtime frida status` reports the Frida CLI path/version, the Python `frida`
binding availability, and — only when a device is connected — whether
`frida-server` appears present (`/data/local/tmp/frida-server`, configurable).
Without a device the server status is `UNKNOWN`. Frida is never started
automatically and no binaries are downloaded.

## Attach (explicit)

`runtime frida attach --session <id> --profiles <names> [--duration N]` spawns the
selected package on the explicitly selected device, loads the generated
observation-only script, collects `send()` messages for a bounded duration, then
detaches. It requires the Python `frida` binding and a live device; otherwise it
returns `UNAVAILABLE`/`FAILED`.

## Observation-only hook profiles

Profiles (`backend/app/runtime/hooks.py`): `lifecycle`, `intents`, `webview`,
`reflection`, `dynamic_loading`, `crypto`, `network`, `file_access`, `jni`,
`native_dangerous`. The generated script overrides each target's implementation
only to **log arguments and the return value, then calls the original and returns
it unchanged**. Hooks must never modify return values, bypass security checks,
disable TLS, inject commands, alter authentication, dump credentials, bypass
permissions, or patch memory.

## Installation

`pip install frida-tools` (explicit user opt-in) plus a matching `frida-server`
on the device. This project never installs Frida for you.

## Bounds

Emitted events are capped (`ASF_RUNTIME_OBSERVATION_LIMIT`) both agent-side (the
script stops after the cap) and host-side (persistence cap). Argument/return
summaries are masked and truncated.
