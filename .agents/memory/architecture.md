# Architecture

Durable architectural decisions and constraints for SeedPass.

## TypeScript port: Python stays authoritative until parity is proven

The `port/typescript-web-extension` effort re-implements SeedPass as a
protocol-compatible TypeScript core with thin adapters (CLI, static/PWA web
app, browser extension, optional Tauri desktop) — not a screen-by-screen port
of the Python TUI. The Python implementation remains the reference, and the
TypeScript implementation becomes authoritative only after deterministic
derivation, vault compatibility, sync compatibility, and safety tests pass.
Hard non-goals: no plaintext seeds/passwords/TOTP secrets/private keys in
browser `localStorage`, no hosted-server requirement, no analytics/telemetry,
no large frontend dependency graph for cryptographic behavior.

Authoritative source:
- docs/typescript_web_extension_port_plan.md (§1–3)
