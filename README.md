# Aggregator Provision

Go implementation of a materializing Aggregator Server, developed conformance-first against the aggregator conformance suite.

## Development

### Dependencies

- Go 1.26.1 or newer, matching `go.mod`.
- Oxigraph CLI, available as `oxigraph` on `PATH`.
- `aggregator-conformance`, either as a sibling checkout at `../aggregator-conformance` or as an executable on `PATH`.

Install Oxigraph with Cargo:

```sh
cargo install oxigraph-cli
```

Oxigraph's Cargo build requires a recent Rust/Cargo toolchain and may require Clang for the RocksDB bindings.
Cargo installs binaries in `~/.cargo/bin` by default. Add that directory to your shell `PATH` if `oxigraph` is not found:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

For a permanent Bash setup:

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
```

Verify the installation:

```sh
oxigraph --version
```

The materializer uses `oxigraph load` to load RDF source documents and `oxigraph query` to write materialized CONSTRUCT or SELECT outputs. Official CLI installation docs are at <https://docs.rs/oxigraph-cli>.

Run the Go test suite and emit the JSON stream used by the conformance converter:

```sh
make test
```

Run the full conformance workflow when `aggregator-conformance` is available on `PATH`:

```sh
make conformance-check
```

By default the Makefile uses a sibling checkout at `../aggregator-conformance`.
Override it if the CLI is installed elsewhere:

```sh
make conformance-check CONFORMANCE_CLI=aggregator-conformance
```
