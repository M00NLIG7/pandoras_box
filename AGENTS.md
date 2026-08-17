# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Cross-platform qualification boundary

Runtime target/payload contracts are authoritative in `pandoras_box/src/runtime/mission.rs` and `payloads.rs`; the evidence ladder is in `docs/BUILDING.md`. Never mark a payload `live_qualified` or expand the support matrix without an exact packaged-artifact gate. Unknown and contract-only targets must remain pre-authentication outcomes.

## Credential and mission identity boundary

Named credential resolution is authoritative in `pandoras_box/src/runtime/credentials.rs`; operator schema and precedence are in `docs/CREDENTIAL_PROFILES.md`. Keep secret values out of durable identity/artifacts, make selection failures host-local and pre-authentication, and preserve explicit mission reuse semantics in `runtime/runner.rs`.

## Documentation boundary

Documentation and generated documentation are repository-local only. Do not publish, host, upload, or attach them to releases or external documentation channels. Keep release/package automation free of documentation files and documentation-publication steps.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
