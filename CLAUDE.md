# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

This repo accompanies the TOS paper "Encrypted Data Reduction: Removing Redundancy from Encrypted Data in Outsourced Storage" (EDRStore). It contains two near-parallel C++20 codebases plus auxiliary scripts:

- `EDRStore/` — the full EDRStore prototype (client + storage server + key manager).
- `Baseline/` — baseline approaches (Plain, Server-aided MLE, Encrypted Local Compression) used for comparison in the paper. Same module layout as `EDRStore/`.
- `Script/` — Python scripts that download the six paper traces (TENSORFLOW, DOCKER, GCC, CHROM, LINUX, …) into local datasets.
- `upload_bash/` — convenience batch scripts that `cd` into `EDRStore/bin` and invoke `ClientMain -t u -m 2` over a hard-coded list of tarballs per dataset (gcc, glibc, gdb, emacs, binutils). Useful templates when running new datasets.

`EDRStore/` and `Baseline/` have separate but mostly identical READMEs, configs, and build scripts. Treat them as two builds of the same system with different reduction policies — do not assume changes in one are mirrored in the other.

## Build and run

Both components use the same workflow. Substitute `EDRStore` ↔ `Baseline` as needed.

```bash
cd EDRStore
bash setup.sh        # first build: cleans, mkdir bin/lib/build, cmake .., make -j4, creates bin/{Containers,Recipes,Cache}, copies config.json to bin/
bash recomplie.sh    # rebuild + wipe stored data in bin/ (NOTE: filename is "recomplie.sh", not "recompile.sh")
./cleanup.sh         # remove bin/, lib/, build/ entirely
```

`recomplie.sh` re-copies the top-level `config.json` into `bin/`. **Edit `EDRStore/config.json` (not `EDRStore/bin/config.json`) and re-run `recomplie.sh`** so changes survive rebuilds. The compiled binaries live in `bin/` and *must* be run from inside `bin/` — they read `config.json` and SSL keys (`../key/...`) by relative path.

The three executables are launched separately, typically on three machines (storage server + key server + client). Order: start `ServerMain` and `KeyManager` first, then run `ClientMain`. Stop the long-running servers with Ctrl+C (handled cleanly by the signal handler).

```bash
cd EDRStore/bin
./ServerMain                                                # storage server (cloud)
./KeyManager                                                # key server
./ClientMain -t u -i <input file> -m <method>               # upload
./ClientMain -t d -i <output file path> -m <method>         # download
```

`-m` semantics differ between the two codebases:
- **EDRStore**: `0` = similar-aware enc, `1` = similar-aware enc + local compression, `2` = full EDR (see `EDR_DESIGN_SET` in `EDRStore/include/const_var.h`).
- **Baseline**: `0` = Plain, `1` = Server-aided MLE, `2` = Encrypted Local Compression (see `CLIENT_ENC_TYPE_SET`).

For batch experiments, `EDRStore/script/trace_exp.py` emits a shell script that walks an input trace folder and produces one `./ClientMain` invocation per file (optionally staging through a ramdisk). `upload_bash/upload_*.sh` shows the production pattern used to run the GCC/glibc/etc. workloads end-to-end.

There is no unit-test target. Validation is done by running the three-process system against real traces and reading the CSV-style `client-log` / `server-log` / `breakdown-*` files written next to the binaries in `bin/`.

## High-level architecture

EDRStore is a **three-party encrypted storage system** with a deduplication + delta-compression + local-compression reduction pipeline. The three parties communicate over mutually-authenticated TLS (`SSLConnection` in `include/network/`, certs under each component's `key/`).

### Client upload pipeline (`EDRStore/src/app/client_main.cc`)

The client is a **6-stage producer/consumer pipeline** wired with lock-free message queues (`include/message_queue/`, type chosen via `MQ_TYPE = LCK_FREE_MQ`). Each stage is a `boost::thread`:

1. `ChunkerFPThd` — content-defined chunking (FastCDC by default, see `include/chunker/chunker_factory.h`) + SHA-256 fingerprint.
2. `PlainSimilarThd` — plaintext feature/super-feature extraction for similarity detection (3 super-features × 4 features per chunk; see `const_var.h`).
3. `KeyGenThd` — server-aided MLE key generation against `KeyManager` over a separate SSL channel.
4. `CipherSimilarThd` — recomputes features on ciphertext (this is the EDR core: detect similarity *after* encryption).
5. `SelectCompThd` — picks delta-vs-local compression per chunk, maintains client-side `CacheMeta` for base chunks.
6. `SenderThd` — frames `SendChunk_t` / recipe batches and ships them to `ServerMain`.

Queue element types and headers are defined once in `include/data_structure.h` (`Chunk_t`, `FeatureChunk_t`, `EncFeatureChunk_t`, `SelectComp2Sender_t`, `SendChunkHeader_t`, etc.). When you add a new pipeline stage, you almost always need a new typedef there plus a `MQFactory<...>` instance in `client_main.cc`.

Download is a 2-thread pipeline: `DataRetrieverThd` ↔ `DownloadWriterThd`.

### Storage server (`EDRStore/src/app/server_main.cc`)

`ServerMain` is a connection-accept loop that spawns one `ServerOptThd` per client SSL session. Inside `ServerOptThd`, per-request worker threads live under `src/server/` and `include/server/`:

- `data_recv_thd` → `dual_dedup_thd` → `data_writer_thd` (write path)
- `data_reader_thd` → `data_decoder_thd` (read path)
- `cache_comp_thd`, `server_opt_thd`, `inform_cache`, `storage_core` — server-side cache management for delta-base chunks.

Two persistent indexes are built via `DatabaseFactory` (`include/database/db_factory.h`): a fingerprint→chunk-address DB and a feature→fingerprint DB. The factory supports `IN_MEMORY_DB`, `LEVELDB_DB`, `ROCKSDB_DB`; `server_main.cc` defaults to `IN_MEMORY_DB`. Chunks land in 4 MiB containers (`MAX_CONTAINER_SIZE` in `const_var.h`) under `Containers/`, file recipes under `Recipes/`, and the base-chunk cache index under `Cache/`.

### Key manager (`EDRStore/src/app/km_main.cc`)

Standalone process running `BasicKM` (`include/key_manager/basic_km.h`). Owns the feature→key index used for server-aided MLE. Per-client requests run as boost threads.

### Reduction policy module (`src/reduction/`, `include/reduction/`)

`dedup_detect`, `delta_comp` (uses bundled `third/xdelta`), and `similar_policy` are shared between client and server-side code. Changes to chunk/feature/recipe layouts must be reflected on both sides — there is no schema versioning.

## Things to know before editing

- **Two near-identical trees**: `EDRStore/include/const_var.h` ↔ `Baseline/include/const_var.h`, etc. Many enums (`CHUNK_STATUS_SET`, `NETWORK_PROTOCOL_SET`, `DATA_TYPE_SET`) appear in both. If you change a wire-protocol enum or a `*_t` struct in `data_structure.h`, you typically need the matching change in the other tree, and clients/servers must be rebuilt together — there is no protocol version negotiation.
- **`EDR_BREAKDOWN`** (defined in `const_var.h`) toggles a parallel set of fine-grained timing fields and the `breakdown-*` log files. Code is sprinkled with `#ifdef EDR_BREAKDOWN` blocks; keep the read/write order consistent on both sides of `breakdown_stat_file_name` (binary serialization is positional, no field tags).
- **Working directory matters**: SSL cert paths (`../key/server/...`) and stat files (`client-stat`, `client-log`, `server-log`, `breakdown-stat`) are resolved relative to CWD. Always `cd EDRStore/bin` (or `Baseline/bin`) before running, exactly as the upload scripts do.
- **OpenSSL ≥ 1.1 is required** (CMake hard-fails otherwise). System packages needed: `g++ cmake libssl-dev libleveldb-dev liblz4-dev libzstd-dev librocksdb-dev libboost-all-dev libsnappy-dev libbz2-dev libjemalloc-dev`.
- **Release vs Debug**: `CMakeLists.txt` defaults to `Release` (`-O3`) and links `jemalloc`. The Debug profile enables AddressSanitizer (`-fsanitize=address`) and drops jemalloc — flip `CMAKE_BUILD_TYPE` at the top of the CMakeLists when you need it.
- **`bin/` is wiped by `recomplie.sh`**. Any `client-log` / `server-log` you want to keep should be moved out first.
