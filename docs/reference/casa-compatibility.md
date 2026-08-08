# casa compatibility contract

This component runs as a casa specialist. casa applies a set of gates when it
installs a bundled plugin — naming rules, length limits, marker scans, an
environment-declaration grammar — and a plugin that violates one of them is
**refused**, not warned about.

So this repository holds its own copy of each of those rules, and refuses what
casa would refuse, before an install ever reaches casa. The copies live in
`tests/test_component.py`, which is where the component's install-time
guarantees are checked; each is registered in `CASA_COPIES` and carries a
`#: casa contract:` line pointing here.

The copies exist because casa is **not importable** from the test container:
casa's modules import `jsonschema` and `yaml`, and importing a gate in order to
test a copy of it would be the copy testing itself. `callbacks.py` reaches a
real casa through `$CASA_ROOT` at runtime; the suite has no such root.

## Version range

The values below were taken from **casa v0.148.0** and **casa v0.155.0** — the
version each row names is the version its value was read from.

**This table is a copy, and a copy is a claim about another codebase.** Nothing
in this commit can show that a row matches what casa actually defines — no casa
source ships here. What the rows ARE, verifiably, is the contract this component
holds itself to: the suite refuses an install that would violate any of them,
whatever casa turns out to do. That is the part a reader can check.

What makes the other half checkable is the `$CASA_ROOT` arm of
`tests/test_component.py`: point it at a casa checkout and every value here is
compared against the real symbol. Without a checkout, the suite checks only that
the copies and this table agree with each other — which catches drift between
them, and nothing about casa.

The component **requires casa >= v0.155.0**, because the environment-declaration
rows below do not exist in earlier versions.

**Nothing declares that requirement and nothing enforces it.** There is no
version field in the plugin manifest, no handshake, and no check at install:
this page and `plugins/bank-feed/README.md` are the only places it is written
down. Installing under an older casa fails at the point the missing behaviour is
needed, with whatever error casa raises there. Stated plainly rather than left
to be discovered.

## The copied values

| local name | casa symbol | casa version | what it constrains |
| --- | --- | --- | --- |
| `FORBIDDEN_MARKERS` | `authored_markers.FORBIDDEN_MARKERS` | v0.148.0 | Substrings no authored file may contain: template delimiters and the structural tags that frame a prompt. A file containing one is refused at install, so no authored file in this repository may contain a literal fence marker. |
| `HTML_TAG_OPEN_RE` | `authored_markers.HTML_TAG_OPEN_RE` | v0.148.0 | An angle bracket followed by an optional slash and then a letter is refused. Deliberately conservative: prose like `a < b` is refused too, which is what makes a literal tag unshippable inside plugin markdown. |
| `SETUP_TOOL_RE` | `plugin_store._SETUP_TOOL_RE` | v0.148.0 | The name shape a `casa.setupTool` must have: `setup_` followed by up to 64 lowercase, digit or underscore characters. A manifest naming its setup tool anything else is a refused install. |
| `MAX_SUMMARY_LEN` | `plugin_store._PROTECTED_TOOL_SUMMARY_MAX_CHARS` | v0.148.0 | The longest a `protectedTools` summary may be. The summary must also pass casa's unsafe-text predicate, which admits no control characters — so no newline, whatever the length. |
| `MAX_EFFECTIVE_LEN` | `plugin_callbacks.MAX_EFFECTIVE_LEN` | v0.148.0 | The longest a tool's effective registry name may be, measured on the SCOPED name `<slug>.<manifest name>` rather than on the manifest name alone. |
| `METADATA_FILENAME` | `plugin_store.METADATA_FILENAME` | v0.148.0 | The artifact-metadata filename casa writes into an installed plugin tree, and excludes from the tree digest. A pinned digest computed without excluding it will not match the one casa computes. |
| `PLUGIN_ENV_DECLARATION_PREFIX` | `plugin_store.PLUGIN_ENV_DECLARATION_PREFIX` | v0.155.0 | The prefix every name in `casa.setupProvides` must carry. A declared name is bound for the whole session — casa pins it to the empty string while unresolved — so the declaration namespace is fenced, and a name outside the prefix is a refused install, not a warning. |
| `ENV_DECLARATION_RE` | `plugin_store._DECLARABLE_ENV_NAME_RE` | v0.155.0 | The full grammar a declarable name must satisfy, not merely the prefix. This row cites a symbol NAME rather than a line on purpose: the symbol was renamed in v0.155.0 when it was split from the `${VAR}` reference scanner it had been shadowing, and citing the name meant the rename surfaced as a failing cross-check instead of a silent comparison against the wrong pattern. |
| `MAX_ENV_DECLARATIONS` | `plugin_store._MAX_ENV_DECLARATIONS` | v0.155.0 | How many environment names one plugin may declare. Exceeding it is a refused install. |
| `CASA_OWNED_ENV_OPTIONS` | `plugin_store.CASA_OWNED_ENV_OPTIONS` | v0.155.0 | Environment variables a plugin may REFERENCE but never supply and never declare, mapped to the app option casa exports each from. The mapping is also the remediation: the fix for a missing one is its option, never a plugin env file. |
| `MCP_JSON_VAR_RE` | `specialist_install._MCP_JSON_VAR_RE` | v0.155.0 | The `${VAR}` and `${VAR:-default}` interpolation syntax casa carves out of each `.mcp.json` string leaf before the marker scan. Without the carve-out a defaulted reference keeps its `${` and trips the forbidden markers, refusing a bundled plugin for syntax a standalone plugin may use freely. The named `default` group is load-bearing for expansion. |
| `REQUIRED_REF_RE` | `plugin_env_extractor._VAR_PATTERN` | v0.155.0 | Which references count as REQUIREMENTS for the withhold gate: bare `${VAR}` only. A `${VAR:-default}` is satisfied by its own default, so withholding an install for it would be wrong. |
| `ANY_REF_RE` | `plugin_env_extractor._ANY_VAR_PATTERN` | v0.155.0 | Both documented reference forms. Consent enumeration and the name-collision preflight use this one, so a default cannot hide a name claim. |

## The authorization-callback contract

`plugins/bank-feed/server/callbacks.py` implements the **consumer half of
casa's authorization-callback contract**, introduced in casa v0.147. The
division of labour is fixed by casa:

* **casa owns** mint, collect and ack; the spool file grammars; the artifact
  TTLs; and redelivery, including the nudge ladder that resumes a collection
  across restarts (publish +0 s, +60 s, +3 min, +8 min, +30 min, +2 h; six
  accepted dispatches).
* **this plugin owns** the durable attempt row, the collector's lease,
  every validation that must happen before an authorization code is
  exchanged, and the outcome it publishes back.

Two consequences a reader needs, because they are the reason the module is
shaped as it is:

* **A plugin may not wait, poll or schedule.** A specialist has no timer and no
  background thread. A collection pass is therefore whatever a nudged turn
  runs, start to finish, and the continuation mechanism is casa's ladder.
* **casa exposes no callback-consumer protocol version.** The compatibility
  gate in `callbacks.py` checks casa's in-band schema constant, the consumer API
  surface it calls, and the one TTL constant it copies. That is a
  best-available check, not a version handshake: the hold semantics of a
  `.collect-*` inode and the construction of a result record can both change
  while all three halves keep passing. A dedicated protocol constant is asked
  for in casa's own issue tracker (`casa#401`).

`RESULT_TTL_S` is the only casa constant `callbacks.py` duplicates, and it is
derived from the gate's own tuple rather than written out twice, so the copy
under the gate is the only copy.

## How this stays true

The table is **machine-read**, not decorative. `tests/test_component.py` parses
it and holds it to `CASA_COPIES` in both directions: a constant registered
without a row here fails, and a row here naming an unregistered constant fails.
Neither the code nor this document can drift alone.

The values themselves are cross-checked against a real casa by
`test_the_local_copy_of_casas_rule_still_matches_casas_own`, which re-derives
every registered constant from casa's own source by parsing it. That arm runs
wherever `$CASA_ROOT` points at a casa checkout — a developer machine, which is
the only place a casa version bump can be made — and is a no-op, never a skip,
where it does not.

**When casa changes one of these values**, the copy, the version in this table,
and the sentence describing it move together in one change. The `$CASA_ROOT`
arm is how the mismatch is found before it ships; a reader without a casa
checkout has this table, and nothing else, so a stale row is a false statement
to them.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `tests/test_component.py`
- `plugins/bank-feed/server/callbacks.py`

**Tests**
- `tests/test_component.py`

**Related**
- [`architecture/bank-linking.md`](../architecture/bank-linking.md)
<!-- END SOURCEMAP -->
