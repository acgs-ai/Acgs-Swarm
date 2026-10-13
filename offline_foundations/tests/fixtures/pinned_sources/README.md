# Pinned source-text inputs

These six `.py.txt` files are exact source bytes used by the hash-guarded pure
reference tests. They are data, not importable backend packages. The test harness
executes only its explicitly selected pure function ASTs, or the audited pure
confidence module; it never executes model/serving imports or module bodies.

`provenance.json` records original commit-pinned URLs and byte hashes. Laya and
SGLang license texts are retained unchanged. The ACGS guard reference belongs
to this repository and is pinned to its recorded upstream revision. No models,
tokenizers, source-tree inventories, credentials, database files or execution
logs are included in these inputs.
