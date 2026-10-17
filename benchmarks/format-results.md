# Rust format sweep

Date: 2026-10-17T09:26:40+00:00 · Host: brewtop

Binary: ratarmount 0.1.34 · Git: `c5414bade48e04d2ac34ec8b6e6cde9167f37d43`

CPU: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz · RAM: MemTotal:       65280384 kB

One-minute load before/after: 12.11 / 9.70

Corpus: 1000 × 32 KiB files in 10 folders + 64 MiB seeded incompressible blob; fixed mtime 1792108800. Models: 48 tensors, 64 MiB F16 bytes.

## Overview

| Format (fixture) | Size | Cold index (s) | Cold mount (s) | Warm mount (s) | Peak RSS warm (MiB) | Random cat (ms) | 64 KiB pread (ms) | Sequential (MiB/s) | Find (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| tar (`corpus.tar`) | 95.8 MiB | 0.313 | 0.128 | 0.058 | 21.7 | 2.1 | 0.1 | 10559 | 7.8 |
| tar.gz (`corpus.tar.gz`) | 68.3 MiB | 0.236 | 0.266 | 0.115 | 20.4 | 10.3 | 4.1 | 10767 | 6.1 |
| tar.bz2 (`corpus.tar.bz2`) | 72.4 MiB | 26.884 | 18.583 | 0.139 | 92.2 | — | — | — | — |
| tar.xz (`corpus.tar.xz`) | 68.0 MiB | 0.374 | 0.383 | 0.013 | 20.2 | 39.2 | 5.5 | 17270 | 3.1 |
| tar.zst (`corpus.tar.zst`) | 67.9 MiB | 0.073 | 0.068 | 0.066 | 20.0 | 2.8 | 1.9 | 14784 | 3.1 |
| tar.lz4 (`corpus.tar.lz4`) | 68.1 MiB | 0.070 | 0.067 | 0.068 | 39.7 | 2.0 | 0.8 | 18297 | 2.9 |
| zip-deflate (`corpus.zip`) | 68.3 MiB | 0.032 | 0.067 | 0.067 | 20.6 | 1.1 | 0.0 | 17922 | 2.9 |
| zip-store (`corpus-store.zip`) | 95.3 MiB | 0.043 | 0.067 | 0.066 | 20.3 | 1.1 | 0.1 | 16665 | 3.8 |
| cpio (`corpus.cpio`) | 95.4 MiB | 0.032 | 0.067 | 0.068 | 20.0 | 1.1 | 0.1 | 16887 | 3.2 |
| ar (`corpus.ar`) | 95.3 MiB | 0.035 | 0.070 | 0.018 | 21.2 | 1.0 | 0.1 | 16954 | 2.6 |
| iso (`corpus.iso`) | 95.7 MiB | 0.033 | 0.067 | 0.015 | 20.3 | — | — | — | — |
| ext4 (`corpus.ext4`) | 152.0 MiB | 0.008 | 0.014 | 0.015 | 18.4 | 1.3 | 0.1 | 1133 | 7.2 |
| mbr/ext4 (`corpus-mbr.img`) | 153.0 MiB | 0.009 | 0.015 | 0.014 | 18.4 | 1.3 | 0.1 | 1138 | 6.5 |
| qcow2/ext4 (`corpus.qcow2`) | 96.4 MiB | 0.009 | 0.019 | 0.018 | 18.7 | 1.4 | 0.1 | 986 | 7.9 |
| safetensors (`model.safetensors`) | 64.0 MiB | 0.036 | 0.067 | 0.015 | 21.1 | — | — | — | — |
| gguf (`model.gguf`) | 64.0 MiB | 0.029 | 0.067 | 0.015 | 20.8 | — | — | — | — |
| nested-tar (`nested.tar`) | 136.6 MiB | 0.115 | 0.131 | 0.133 | 29.1 | 1.1 | 0.1 | 16437 | 5.0 |
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
| corpus.tar.bz2 | members | error | bzip2 -1 -c; expected 1001 regular files |
| corpus.iso | reads | error | xorriso Rock Ridge; missing bandwidth member /home/brewerm/.cache/claude-tmp/fmtbench-tmp/ratarmount-formats.IEJum7/mnt.h9ACwq/blob.bin |
| model.safetensors | members | error | python3 stdlib; 48 F16 tensors; 64 MiB payload; expected 98 regular files |
| model.gguf | members | error | python3 stdlib; 48 F16 tensors; 64 MiB payload; expected 97 regular files |

## Methodology and caveats

- Rust binary only. Each cold index uses `-f --no-mount -c --index-file … --index-minimum-file-count 0`; cold/warm foreground mounts rebuild/reuse the same index. Nested TAR uses `-r`.
- Cold means index recreation, not a flushed OS page cache. One cold index and one cold/warm mount per fixture. Mount readiness includes polling and a successful directory listing; VmHWM is sampled immediately after readiness (unavailable values are skips).
- Read metrics run on the warm mount: seeded random cat, median of 15 (32 KiB members, 64 KiB tensors for models); 15 exact 64 KiB os.pread calls on one open bandwidth member; median of 3 full cat bandwidth samples. Find is one walk after reads. SHA-256 verifies the bandwidth member after sequential reads.
- Regular-file membership is checked before reads: corpus count + blob; twice that for nested ZIP+tar.gz; models include 48 tensor JSON sidecars, metadata JSON, and safetensors raw-header JSON (98/97 files). Filesystem bookkeeping directories do not add regular members.
- Model bandwidth uses layer/47/weight (8 MiB), nested bandwidth uses corpus.zip/blob.bin, partition images use p1/blob.bin. Producer details are in CSV notes. Missing producer tools are skips; producer/daemon/read/count/checksum failures are errors.
- FUSE plus page cache is not disk speed. This is a single-host directional comparison; process startup and cached reads dominate small timings. Build profile, load, compression layout, temporary storage and fixture size matter. No Python ratarmount baseline is involved.
