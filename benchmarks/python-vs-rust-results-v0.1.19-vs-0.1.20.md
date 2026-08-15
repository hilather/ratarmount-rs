# Three-way bench: Python ratarmount vs Rust v0.1.19 vs v0.1.20

Host: Ubuntu 24.04 x86_64, FUSE, single run each (directional, not publication-grade).

- **Python**: sibling checkout via `benchmarks/.venv-py` (`ratarmount 1.3.0`). Numbers from the v0.1.20 suite.
- **Rust v0.1.19**: GitHub Release `ratarmount-0.1.19-ubuntu-24.04-x86_64`. Separate suite immediately after v0.1.20.
- **Rust v0.1.20**: `cargo build --release` of `e62807e` (density work + cheap `list_dirents` wrappers + FUSE `readlink` cache + SqliteIndex format sizes).
- Harness: [compare-python-vs-rust.sh](https://github.com/hilather/ratarmount-rs/blob/v0.1.20/benchmarks/compare-python-vs-rust.sh).

**v0.1.20 vs v0.1.19** is the post-release density + cheap-list work. Sub-3% is noise on this harness.

## `nested-tar.tar`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 338.3 ms |  60.5 ms |  61.3 ms | ≈ same | v0.1.20 **5.52×** |
| Mount time | warm | 290.4 ms |  64.0 ms |  62.5 ms | ≈ same | v0.1.20 **4.65×** |
| Peak RSS | cold | 116.2 MiB |  15.0 MiB |  15.3 MiB | ≈ same | v0.1.20 **7.58×** |
| Peak RSS | warm | 116.2 MiB |  15.0 MiB |  15.4 MiB | ≈ same | v0.1.20 **7.55×** |
| Random cat (median) | cold |  4.1 ms |  3.1 ms |  2.3 ms | v0.1.20 **1.37×** | v0.1.20 **1.79×** |
| Random cat (median) | warm |  3.1 ms |  2.3 ms |  2.2 ms | v0.1.20 **1.06×** | v0.1.20 **1.42×** |
| find walk | cold |  5.7 ms |  4.5 ms |  3.1 ms | v0.1.20 **1.45×** | v0.1.20 **1.84×** |
| find walk | warm |  3.6 ms |  3.1 ms |  2.4 ms | v0.1.20 **1.29×** | v0.1.20 **1.50×** |
| Seq. bandwidth | cold | 0.6 MiB/s | 0.0 MiB/s | 0.0 MiB/s | — | — |
| Seq. bandwidth | warm | 0.9 MiB/s | 0.0 MiB/s | 0.0 MiB/s | — | Python **86.00×** |

## `empty-1k.tar`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 338.9 ms |  60.7 ms |  61.6 ms | ≈ same | v0.1.20 **5.50×** |
| Mount time | warm | 299.4 ms |  60.5 ms |  63.2 ms | v0.1.19 **1.04×** | v0.1.20 **4.74×** |
| Peak RSS | cold | 116.2 MiB |  15.4 MiB |  15.9 MiB | ≈ same | v0.1.20 **7.31×** |
| Peak RSS | warm | 116.2 MiB |  15.6 MiB |  15.7 MiB | ≈ same | v0.1.20 **7.39×** |
| Random cat (median) | cold |  2.2 ms |  2.0 ms |  2.1 ms | v0.1.19 **1.05×** | v0.1.20 **1.06×** |
| Random cat (median) | warm |  2.4 ms |  3.2 ms |  2.6 ms | v0.1.20 **1.23×** | Python **1.09×** |
| find walk | cold |  8.1 ms |  4.5 ms |  5.1 ms | v0.1.19 **1.13×** | v0.1.20 **1.59×** |
| find walk | warm |  8.2 ms |  7.7 ms |  5.8 ms | v0.1.20 **1.33×** | v0.1.20 **1.41×** |

## `small-100.tar`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 340.6 ms |  61.3 ms |  60.7 ms | ≈ same | v0.1.20 **5.61×** |
| Mount time | warm | 290.6 ms |  63.2 ms |  63.1 ms | ≈ same | v0.1.20 **4.61×** |
| Peak RSS | cold | 116.2 MiB |  15.3 MiB |  15.3 MiB | ≈ same | v0.1.20 **7.59×** |
| Peak RSS | warm | 116.4 MiB |  15.1 MiB |  15.4 MiB | ≈ same | v0.1.20 **7.56×** |
| Random cat (median) | cold |  4.3 ms |  3.1 ms |  2.5 ms | v0.1.20 **1.22×** | v0.1.20 **1.72×** |
| Random cat (median) | warm |  2.5 ms |  2.4 ms |  4.2 ms | v0.1.19 **1.75×** | Python **1.69×** |
| find walk | cold |  5.1 ms |  3.6 ms |  3.1 ms | v0.1.20 **1.16×** | v0.1.20 **1.65×** |
| find walk | warm |  2.7 ms |  2.6 ms |  5.3 ms | v0.1.19 **2.04×** | Python **1.96×** |
| Seq. bandwidth | cold | 15.2 MiB/s | 21.4 MiB/s | 25.9 MiB/s | v0.1.20 **1.21×** | v0.1.20 **1.70×** |
| Seq. bandwidth | warm | 22.0 MiB/s | 28.2 MiB/s | 13.7 MiB/s | v0.1.19 **2.06×** | Python **1.61×** |

## `large-64m.tar`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 287.3 ms |  72.6 ms |  61.7 ms | v0.1.20 **1.18×** | v0.1.20 **4.66×** |
| Mount time | warm | 339.5 ms |  61.2 ms |  63.1 ms | v0.1.19 **1.03×** | v0.1.20 **5.38×** |
| Peak RSS | cold | 116.4 MiB |  15.0 MiB |  15.2 MiB | ≈ same | v0.1.20 **7.63×** |
| Peak RSS | warm | 116.2 MiB |  14.8 MiB |  15.2 MiB | ≈ same | v0.1.20 **7.65×** |
| Random cat (median) | cold |  39.6 ms |  9.9 ms |  9.6 ms | ≈ same | v0.1.20 **4.13×** |
| Random cat (median) | warm |  39.7 ms |  11.5 ms |  10.3 ms | v0.1.20 **1.12×** | v0.1.20 **3.87×** |
| find walk | cold |  2.7 ms |  2.2 ms |  2.2 ms | ≈ same | v0.1.20 **1.23×** |
| find walk | warm |  2.5 ms |  2.5 ms |  2.5 ms | ≈ same | ≈ same |
| Seq. bandwidth | cold | 1660.7 MiB/s | 6604.8 MiB/s | 6608.2 MiB/s | ≈ same | v0.1.20 **3.98×** |
| Seq. bandwidth | warm | 1418.3 MiB/s | 5662.2 MiB/s | 6952.0 MiB/s | v0.1.20 **1.23×** | v0.1.20 **4.90×** |

## `small-100.tar.gz`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 354.4 ms |  61.3 ms |  65.3 ms | v0.1.19 **1.07×** | v0.1.20 **5.43×** |
| Mount time | warm | 563.0 ms |  64.5 ms |  63.9 ms | ≈ same | v0.1.20 **8.81×** |
| Peak RSS | cold | 116.2 MiB |  21.2 MiB |  21.2 MiB | ≈ same | v0.1.20 **5.47×** |
| Peak RSS | warm | 350.8 MiB |  14.5 MiB |  14.4 MiB | ≈ same | v0.1.20 **24.33×** |
| Random cat (median) | cold |  2.4 ms |  8.3 ms |  5.4 ms | v0.1.20 **1.54×** | Python **2.23×** |
| Random cat (median) | warm |  4.1 ms |  10.9 ms |  10.4 ms | v0.1.20 **1.05×** | Python **2.56×** |
| find walk | cold |  3.0 ms |  2.5 ms |  2.5 ms | ≈ same | v0.1.20 **1.20×** |
| find walk | warm |  5.1 ms |  2.7 ms |  2.4 ms | v0.1.20 **1.13×** | v0.1.20 **2.13×** |
| Seq. bandwidth | cold | 28.3 MiB/s | 5.3 MiB/s | 5.3 MiB/s | ≈ same | Python **5.29×** |
| Seq. bandwidth | warm | 15.8 MiB/s | 4.3 MiB/s | 4.5 MiB/s | v0.1.20 **1.06×** | Python **3.48×** |

## `small-100.tar.bz2`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 454.4 ms | 1.512 s | 1.738 s | v0.1.19 **1.15×** | Python **3.83×** |
| Mount time | warm | 396.9 ms |  62.1 ms |  65.3 ms | v0.1.19 **1.05×** | v0.1.20 **6.08×** |
| Peak RSS | cold | 121.6 MiB |  27.6 MiB |  27.7 MiB | ≈ same | v0.1.20 **4.38×** |
| Peak RSS | warm | 116.2 MiB |  20.6 MiB |  20.6 MiB | ≈ same | v0.1.20 **5.63×** |
| Random cat (median) | cold |  14.4 ms |  14.0 ms |  13.9 ms | ≈ same | v0.1.20 **1.04×** |
| Random cat (median) | warm |  23.2 ms |  12.9 ms |  14.4 ms | v0.1.19 **1.11×** | v0.1.20 **1.62×** |
| find walk | cold |  4.7 ms |  3.1 ms |  2.3 ms | v0.1.20 **1.35×** | v0.1.20 **2.04×** |
| find walk | warm |  5.6 ms |  2.4 ms |  2.4 ms | ≈ same | v0.1.20 **2.33×** |
| Seq. bandwidth | cold | 4.5 MiB/s | 32.5 MiB/s | 4.0 MiB/s | v0.1.19 **8.21×** | Python **1.15×** |
| Seq. bandwidth | warm | 7.3 MiB/s | 4.4 MiB/s | 3.8 MiB/s | v0.1.19 **1.16×** | Python **1.91×** |

## `small-100.tar.xz`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 340.2 ms |  62.4 ms |  60.7 ms | ≈ same | v0.1.20 **5.60×** |
| Mount time | warm | 296.8 ms |  75.2 ms |  61.0 ms | v0.1.20 **1.23×** | v0.1.20 **4.87×** |
| Peak RSS | cold | 116.2 MiB |  28.7 MiB |  28.8 MiB | ≈ same | v0.1.20 **4.03×** |
| Peak RSS | warm | 116.2 MiB |  14.0 MiB |  14.2 MiB | ≈ same | v0.1.20 **8.19×** |
| Random cat (median) | cold |  5.5 ms |  13.4 ms |  11.6 ms | v0.1.20 **1.15×** | Python **2.11×** |
| Random cat (median) | warm |  7.0 ms |  13.2 ms |  12.5 ms | v0.1.20 **1.05×** | Python **1.78×** |
| find walk | cold |  3.7 ms |  2.7 ms |  2.3 ms | v0.1.20 **1.17×** | v0.1.20 **1.61×** |
| find walk | warm |  2.9 ms |  3.0 ms |  2.7 ms | v0.1.20 **1.11×** | v0.1.20 **1.07×** |
| Seq. bandwidth | cold | 10.9 MiB/s | 6.5 MiB/s | 6.2 MiB/s | v0.1.19 **1.03×** | Python **1.75×** |
| Seq. bandwidth | warm | 15.0 MiB/s | 6.5 MiB/s | 6.3 MiB/s | v0.1.19 **1.03×** | Python **2.38×** |

## `small-100.tar.zst`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 338.3 ms |  63.7 ms |  62.6 ms | ≈ same | v0.1.20 **5.40×** |
| Mount time | warm | 340.2 ms |  63.2 ms |  63.3 ms | ≈ same | v0.1.20 **5.37×** |
| Peak RSS | cold | 116.2 MiB |  27.3 MiB |  27.4 MiB | ≈ same | v0.1.20 **4.24×** |
| Peak RSS | warm | 116.2 MiB |  14.2 MiB |  14.1 MiB | ≈ same | v0.1.20 **8.23×** |
| Random cat (median) | cold |  4.1 ms |  2.4 ms |  2.4 ms | ≈ same | v0.1.20 **1.69×** |
| Random cat (median) | warm |  5.5 ms |  9.9 ms |  10.1 ms | ≈ same | Python **1.84×** |
| find walk | cold |  4.7 ms |  2.8 ms |  2.6 ms | v0.1.20 **1.08×** | v0.1.20 **1.81×** |
| find walk | warm |  5.1 ms |  2.6 ms |  2.4 ms | v0.1.20 **1.08×** | v0.1.20 **2.13×** |
| Seq. bandwidth | cold | 12.3 MiB/s | 31.6 MiB/s | 23.3 MiB/s | v0.1.19 **1.36×** | v0.1.20 **1.89×** |
| Seq. bandwidth | warm | 12.1 MiB/s | 6.1 MiB/s | 6.4 MiB/s | v0.1.20 **1.05×** | Python **1.88×** |

## `small-100.zip`

| Metric | Scenario | Python 1.3.0 | Rust v0.1.19 | Rust v0.1.20 | v0.1.20 vs v0.1.19 | v0.1.20 vs Python |
|--------|----------|--------------|--------------|-----------|-----------------|----------------|
| Mount time | cold | 338.9 ms |  71.7 ms |  62.0 ms | v0.1.20 **1.16×** | v0.1.20 **5.47×** |
| Mount time | warm | 341.5 ms |  70.5 ms |  63.6 ms | v0.1.20 **1.11×** | v0.1.20 **5.37×** |
| Peak RSS | cold | 116.2 MiB |  14.5 MiB |  14.5 MiB | ≈ same | v0.1.20 **8.02×** |
| Peak RSS | warm | 116.2 MiB |  14.5 MiB |  14.5 MiB | ≈ same | v0.1.20 **7.99×** |
| Random cat (median) | cold |  2.9 ms |  4.7 ms |  4.5 ms | v0.1.20 **1.04×** | Python **1.56×** |
| Random cat (median) | warm |  2.9 ms |  3.9 ms |  2.5 ms | v0.1.20 **1.53×** | v0.1.20 **1.13×** |
| find walk | cold |  3.7 ms |  5.5 ms |  5.5 ms | ≈ same | Python **1.49×** |
| find walk | warm |  3.6 ms |  4.0 ms |  3.3 ms | v0.1.20 **1.21×** | v0.1.20 **1.09×** |
| Seq. bandwidth | cold | 21.9 MiB/s | 17.9 MiB/s | 14.7 MiB/s | v0.1.19 **1.22×** | Python **1.49×** |
| Seq. bandwidth | warm | 20.4 MiB/s | 18.4 MiB/s | 21.7 MiB/s | v0.1.20 **1.18×** | v0.1.20 **1.06×** |

## Geometric-mean factors

Factor **>1 ⇒ first named better**. Times: other/this. Bandwidth: this/other. RSS: other/this.

| Metric | Scenario | v0.1.20 vs Python | v0.1.20 vs v0.1.19 | v0.1.19 vs Python |
|--------|----------|----------------|-----------------|-------------------|
| Mount time | cold | 3.85× | 1.01× | 3.79× |
| Mount time | warm | 5.43× | 1.02× | 5.30× |
| Peak RSS | cold | 6.03× | 0.99× | 6.09× |
| Peak RSS | warm | 8.53× | 0.99× | 8.60× |
| Random cat (median) | cold | 1.14× | 1.13× | 1.01× |
| Random cat (median) | warm | 0.95× (1.05× other) | 1.03× | 0.93× (1.08× other) |
| find walk | cold | 1.45× | 1.11× | 1.31× |
| find walk | warm | 1.33× | 1.04× | 1.29× |
| Seq. bandwidth | cold | 0.97× (1.03× other) | 0.71× (1.42× other) | 1.38× |
| Seq. bandwidth | warm | 0.73× (1.37× other) | 0.94× (1.06× other) | 0.77× (1.29× other) |

## Notes

- Single-run wall times; treat as directional.
- `empty-1k.tar` + ZIP/TAR `find` are the fairest metadata-density / cheap-readdir probes.
- Compressed `.tar.gz` random/seq still favor Python (rapidgzip / indexed inflate).
- Cold `.tar.bz2` mount is still slower on Rust (block-map build); warm remount is much faster.
- Nested-tar seq bandwidth is not comparable (tiny members; Rust reports a 10-byte file).
