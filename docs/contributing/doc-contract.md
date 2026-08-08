# The documentation contract

> Code is the source of truth. This file is a map; when it and the code disagree, the code wins.

The corpus makes two promises: everything published under `docs/` is there on purpose,
and nothing in it claims something about the code that is not true. This file states
the rules behind those promises and, for each one, whether a machine checks it.

Run the checks with:

```
python3 -m scripts.verify_docs .            # the corpus
python3 -m scripts.verify_docs . --write-nav   # regenerate what is generated
python3 scripts/coverage_ledger.py check .  # every code surface is accounted for
```

Both run in CI on every push.

## Publication is allowlist-only

| Rule | Checked |
|---|---|
| Every file git tracks under `docs/` has an entry in `docs/manifest.yaml`. | yes |
| Every manifest entry names a file git tracks. | yes |
| Only `.md`, `.txt` and `.yaml` are admitted, across everything tracked under `docs/`. | yes |
| Documents live under `architecture/`, `reference/`, `doctrine/` or `contributing/`. | yes |
| A document belongs in the directory that matches how it is read, not how it was written. | no |

Both directions matter. An entry naming a file that exists locally but is untracked
verifies clean here and publishes an empty space, so the corpus that was verified is
not the corpus that shipped.

One path prefix is exempt by name: `docs/superpowers/` is excluded from the corpus in
both directions — it is not demanded by the allowlist, and it may not be manifested,
anchored or linked to either. The rule is a *name*, not a description of what is there,
and it outlives whatever occupied it: anything appearing at that path is working
material by definition, and a reader of this commit does not have it. The exclusion
therefore stays even while the path is empty, because removing it is what would let a
file appear there and walk into the corpus unmanifested.

## A document may not claim what the commit cannot show

| Rule | Checked |
|---|---|
| Anchors are `path::Symbol`, never `path:line`. | yes |
| Every anchor names a path git tracks, inside the repository, that is not a symlink. | yes |
| A Python symbol or YAML key in an anchor resolves. | yes |
| A backticked module name, class-and-method pair or function call in prose exists in the tracked code. | yes |
| The anchor is the *right* code for the claim. | no |
| The prose describes what that code actually does. | no |

Line numbers are refused because they rot the first time anyone edits above them, and
a rotted anchor is worse than none: it points confidently at the wrong thing.

When the prose check fires, the document is wrong. Fix the sentence. Adding the token
to the exemption list in `verify_docs.py` is available and is almost never right — an
exemption for a shape that is genuinely prose is fine, one added to make a false
sentence pass is how the check stops working.

## Generated surfaces are never hand-edited

`docs/llms.txt`, `docs/doctrine/invariants.md`, the routing table in `docs/README.md`,
and every document's **Source & test map** are generated from the manifest by
`verify_docs.py`. Editing one by hand is a staleness failure at the next run, and the
plain `python3 -m scripts.verify_docs .` invocation checks staleness unconditionally
so a local green means a CI green.

Every document therefore carries exactly one ordered `SOURCEMAP` marker pair. Without
it, the document silently has no source map at all.

## Documents stay small

Documents are capped at 25 KB so one fits in context beside the code it describes;
generated indexes at 40 KB. A warning appears from 20 KB. Nothing shards on its own —
exceeding the cap fails, and the fix is to split the document and manifest both
halves. The cap is not raised.

## Invariants are contracts, not assertions

An `INV-` id is defined in exactly one file, on one line: the id in bold, a colon, then
a complete sentence ending in terminal punctuation. `doctrine/publishing.md` is the
worked example. The manifest entry declares the id in `defines_invariants`, and the
declaration is checked both ways against the file.

Every declared invariant must name a test in `invariant_tests` that fails when the
invariant is false. A test bound but never demonstrated red is not evidence; write the
red case first. The sentinel `tests/PINNING-TEST-MISSING` records the debt visibly and
keeps the verifier failing until a real test replaces it — it is a way to be honest
about a gap, not a way to skip one.

The statement must fit on its definition line, because only that line is captured into
the generated index; a wrapped statement is published truncated.

## Every code surface is claimed or excluded

`coverage_ledger.py` enumerates, from the code rather than from a list anyone
maintains: every server module at any depth, every MCP tool, every protected tool in
either declaration form, every entry in the role's allow-list, every environment
variable read or declared, every skill, every file under `scripts/`, and every key of
the configuration schema.

**The tool list is what the server itself answers.** The ledger runs the command each
plugin's `.mcp.json` declares — the same command casa runs — and asks it `tools/list`.

Every step of that comes from a contract rather than from inference, and each one
replaced an inference that was demonstrably wrong. Reading decorator syntax missed a
tool behind every alias spelling anyone tried. Importing the server's modules instead
reimplemented startup, so a tool the entrypoint registered itself was invisible and a
module the entrypoint never imports could change what the gate read. Choosing the
entrypoint by looking for a plausible file inspected a different process from the one
casa launches. A server that will not start, does not answer, answers twice, or answers
with an error is reported as an item rather than as silence: "no tools" and "the server
is broken" must not look alike to a gate.

**The environment arm is still a heuristic**, and it is the one enumerator here that
cannot be exact: there is no runtime registry of "variables this code would read". It
resolves aliases of `os`, of `os.environ` and of `os.getenv`, follows wrapper functions
by shape to a fixed point, binds arguments by keyword as well as position, and applies
lexical shadowing so a local binding of one of those names is not mistaken for the
thing it shadows. What it cannot see is a name that arrives through indirection it
cannot follow — a mapping passed in from a caller, a name computed at runtime. The
declaration side (`.mcp.json`, `casa.setupProvides`) is exact and backstops it.

The other enumerators are still syntactic, and each clause above is worded as it is
because the narrower version was demonstrated to miss a real shape. An enumerator that
stops seeing a surface does not report a gap — it reports success — so each bypass is
pinned by a test. `docs/coverage.yaml` must map each
one to a corpus document or exclude it with a stated reason, and the match is checked
both ways.

"Internal" is not a reason. A reason says what the surface is and why no reader needs
a document for it. If more than a handful of modules are excluded, the corpus is
incomplete and the honest fix is another document.

## When you change the code

1. Change the code and its tests.
2. Update the document that `covers` what you changed — its source map lists them.
3. Run the two commands at the top of this file.
4. If you added a surface, the ledger will tell you before CI does.

## Source & test map

<!-- BEGIN SOURCEMAP -->
<!-- generated by scripts/verify_docs.py --write-nav; do not hand-edit -->

**Source**
- `scripts/verify_docs.py`
- `scripts/coverage_ledger.py`

**Tests**
- `tests/test_verify_docs.py`
- `tests/test_coverage_ledger.py`

**Related**
- [`doctrine/publishing.md`](../doctrine/publishing.md)
<!-- END SOURCEMAP -->
