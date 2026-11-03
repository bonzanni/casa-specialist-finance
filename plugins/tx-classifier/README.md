# tx-classifier

The intelligence half of transaction classification for the finance
specialist. A single skill — no server, no storage, no MCP config. The
deterministic half (rule engine, queue, workflow tags, notes) lives in
the sibling bank-feed plugin, whose primitives hold all of this
workflow's durable state.

## Install

Bundled: this plugin is a `plugin/implementation` dependency of the
finance specialist component (`manifest.json`), installed and upgraded
with the bundle exactly like bank-feed. There is nothing to
`plugin_add`; casa publishes it as an owned registry entry
(`finance.tx-classifier`) locked to `specialist:finance`. bank-feed is
always present by construction (same bundle), and the role's existing
`requires: {plugins: [bank-feed], ...}` launch gate keeps the specialist
from ever running without the substrate.

## Role grants it relies on

`role/role.yaml` `tools.allowed` carries `WebSearch` (evidence-ladder
rung 3, counterparty lookups only) and casa's memory reads,
`mcp__casa-framework__search_memory`, `…__open_memory` and
`…__browse_memory_day` (rung 2, casa memory) — shipped in this same
bundle. The memory reads need casa v0.347.0 or later; an older casa
refuses the bundle at inspection. If a tool is missing from a session,
the skill skips that rung.

## Cadence

Neither plugin can schedule. Create a resident reminder; recommended
text is in the skill's "Recommended reminder" section.

## Tests

Part of the repo suite: `tests/test_tx_classifier.py` pins the artifact
shape and the skill's contract seams against shipped bank-feed spellings.
The workflow's real validation is the scenario walkthrough and live use.
