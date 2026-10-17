# Rust format sweep

Date: 2026-10-17T10:00:05+00:00 · Host: brewtop

Binary: ratarmount 0.1.34 · Git: `09d6e67f1b9a3d5623845161822cade0f4b680b9`

CPU: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz · RAM: MemTotal:       65280384 kB

One-minute load before/after: 4.71 / 3.24

Corpus: 1000 × 32 KiB files in 10 folders + 64 MiB seeded incompressible blob; fixed mtime 1792108800. Models: 48 tensors, 64 MiB F16 bytes.

## Overview

| Format (fixture) | Size | Cold index (s) | Cold mount (s) | Warm mount (s) | Peak RSS warm (MiB) | Random cat (ms) | 64 KiB pread (ms) | Sequential (MiB/s) | Find (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| tar (`corpus.tar`) | 95.8 MiB | 0.069 | 0.064 | 0.064 | 21.8 | 0.9 | 0.1 | 19249 | 2.7 |
| tar.gz (`corpus.tar.gz`) | 68.3 MiB | 0.106 | 0.127 | 0.065 | 20.6 | 4.7 | 2.1 | 19489 | 2.6 |
| tar.bz2 (`corpus.tar.bz2`) | 72.4 MiB | 9.433 | 10.123 | 0.064 | 92.5 | 4.5 | 12.2 | 19529 | 3.3 |
| tar.xz (`corpus.tar.xz`) | 68.0 MiB | 0.344 | 0.377 | 0.012 | 19.9 | 35.3 | 5.0 | 19269 | 3.1 |
| tar.zst (`corpus.tar.zst`) | 67.9 MiB | 0.049 | 0.065 | 0.064 | 20.0 | 2.5 | 1.9 | 18805 | 2.6 |
| tar.lz4 (`corpus.tar.lz4`) | 68.1 MiB | 0.055 | 0.065 | 0.066 | 39.7 | 1.4 | 0.6 | 19408 | 3.0 |
| zip-deflate (`corpus.zip`) | 68.3 MiB | 0.036 | 0.064 | 0.064 | 20.5 | 1.0 | 0.0 | 22334 | 2.7 |
| zip-store (`corpus-store.zip`) | 95.3 MiB | 0.037 | 0.064 | 0.064 | 20.4 | 1.0 | 0.1 | 19632 | 2.9 |
| cpio (`corpus.cpio`) | 95.4 MiB | 0.035 | 0.064 | 0.012 | 20.1 | 0.9 | 0.0 | 20647 | 2.6 |
| ar (`corpus.ar`) | 95.3 MiB | 0.034 | 0.066 | 0.013 | 21.4 | 0.9 | 0.0 | 17793 | 2.1 |
| iso (`corpus.iso`) | 95.7 MiB | 0.029 | 0.064 | 0.064 | 20.0 | 0.9 | 0.0 | 19429 | 2.6 |
| ext4 (`corpus.ext4`) | 152.0 MiB | 0.007 | 0.011 | 0.012 | 18.1 | 1.0 | 0.1 | 1321 | 5.4 |
| mbr/ext4 (`corpus-mbr.img`) | 153.0 MiB | 0.007 | 0.011 | 0.011 | 18.5 | 1.0 | 0.0 | 1367 | 5.2 |
| qcow2/ext4 (`corpus.qcow2`) | 96.4 MiB | 0.007 | 0.011 | 0.011 | 18.6 | 0.9 | 0.0 | 1223 | 4.9 |
| safetensors (`model.safetensors`) | 64.0 MiB | 0.025 | 0.064 | 0.011 | 21.3 | 1.0 | 0.1 | 6486 | 4.6 |
| gguf (`model.gguf`) | 64.0 MiB | 0.025 | 0.064 | 0.011 | 21.3 | 0.9 | 0.0 | 7039 | 4.2 |
| nested-tar (`nested.tar`) | 136.6 MiB | 0.107 | 0.126 | 0.125 | 29.3 | 0.9 | 0.0 | 20050 | 4.2 |
| 7z (`corpus.7z`) | — | — | — | — | — | — | — | — | — |
| squashfs (`corpus.squashfs`) | — | — | — | — | — | — | — | — | — |
| fat (`corpus.fat`) | — | — | — | — | — | — | — | — | — |
| exfat (`corpus.exfat`) | — | — | — | — | — | — | — | — | — |

## Skipped / errors

| Fixture | Metric | Status | Reason / producer |
|---|---|---|---|
| corpus.7z | fixture | skip | missing 7z / 7za / 7zz |
| corpus.squashfs | fixture | skip | missing mksquashfs |
| corpus.fat | fixture | skip | missing mformat |
| corpus.exfat | fixture | skip | missing guestfish |

## Methodology and caveats

- Rust binary only. Each cold index uses `-f --no-mount -c --index-file … --index-minimum-file-count 0`; cold/warm foreground mounts rebuild/reuse the same index. Nested TAR uses `-r`.
- Cold means index recreation, not a flushed OS page cache. One cold index and one cold/warm mount per fixture. Mount readiness includes polling and a successful directory listing; VmHWM is sampled immediately after readiness (unavailable values are skips).
- Read metrics run on the warm mount: seeded random cat, median of 15 (32 KiB members, 64 KiB tensors for models); 15 exact 64 KiB os.pread calls on one open bandwidth member; median of 3 full cat bandwidth samples. Find is one walk after reads. SHA-256 verifies the bandwidth member after sequential reads.
- Regular-file membership is checked before reads: corpus count + blob; twice that for nested ZIP+tar.gz; models include 48 tensor JSON sidecars, metadata JSON, and safetensors raw-header JSON (98/97 files). Filesystem bookkeeping directories do not add regular members.
- Model bandwidth uses layer/47/weight (8 MiB), nested bandwidth uses corpus.zip/blob.bin, partition images use p1/blob.bin. Producer details are in CSV notes. Missing producer tools are skips; producer/daemon/read/count/checksum failures are errors.
- FUSE plus page cache is not disk speed. This is a single-host directional comparison; process startup and cached reads dominate small timings. Build profile, load, compression layout, temporary storage and fixture size matter. No Python ratarmount baseline is involved.
