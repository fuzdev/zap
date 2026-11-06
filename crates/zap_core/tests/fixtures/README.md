# zap_core test fixtures

`detection/*.json` are the detection goldens `tests/detection.rs` replays. Each case
pairs a `resource` and its `target` with what the target answers and the `expected`
`Detection`:

- `observed` — the typed queries the detector issues, in order, each with the
  observation it gets back;
- `recorded` — command → output, for the raw read of an uncached `remote` file;
- `content_cache` — entries to seed the content cache with, and `warms`, the entry a
  detection must leave in it.

A `MockConnection` answers from the recordings, so no case touches a real system. The
suite asserts that the detector issues exactly the recorded queries, in order: a read
a detector stops making or starts making fails its cases, as does a file that isn't
valid JSON for the case shape.

The cases are hand-authored. A query has to match what the detector issues exactly; a
mismatch is a loud mock error, never a silent pass.
