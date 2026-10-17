# Rust format sweep

Date: 2026-10-17T10:40:01+00:00 · Host: brewtop

Binary: ratarmount 0.1.34 · Git: `6ffcc4195b5400424d661ece020fa8e37ba170eb`

CPU: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz · RAM: MemTotal:       65280384 kB

One-minute load before/after: 3.27 / 2.57

Corpus: 1000 × 32 KiB files in 10 folders + 64 MiB seeded incompressible blob; fixed mtime 1792108800. Models: 48 tensors, 64 MiB F16 bytes.

## Overview

| Format (fixture) | Size | Cold index (s) | Cold mount (s) | Warm mount (s) | Peak RSS warm (MiB) | Random cat (ms) | 64 KiB pread (ms) | Sequential (MiB/s) | Find (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| tar (`corpus.tar`) | 95.8 MiB | 0.097 | 0.066 | 0.014 | 21.6 | 1.0 | 0.1 | 16654 | 5.0 |
| tar.gz (`corpus.tar.gz`) | 68.3 MiB | 0.129 | 0.128 | 0.064 | 20.6 | 4.6 | 2.1 | 18986 | 2.8 |
| tar.bz2 (`corpus.tar.bz2`) | 72.4 MiB | 9.896 | 10.315 | 0.064 | 92.2 | 3.7 | 12.2 | 18538 | 2.8 |
| tar.xz (`corpus.tar.xz`) | 68.0 MiB | 0.323 | 0.312 | 0.011 | 20.1 | 34.4 | 4.9 | 19210 | 2.8 |
| tar.zst (`corpus.tar.zst`) | 67.9 MiB | 0.038 | 0.064 | 0.064 | 19.8 | 2.4 | 1.8 | 16825 | 2.8 |
| tar.lz4 (`corpus.tar.lz4`) | 68.1 MiB | 0.048 | 0.065 | 0.065 | 35.8 | 1.4 | 0.6 | 18397 | 2.7 |
| zip-deflate (`corpus.zip`) | 68.3 MiB | 0.037 | 0.064 | 0.067 | 20.4 | 1.0 | 0.0 | 16820 | 3.7 |
| zip-store (`corpus-store.zip`) | 95.3 MiB | 0.041 | 0.064 | 0.064 | 20.5 | 0.9 | 0.0 | 19044 | 2.9 |
| cpio (`corpus.cpio`) | 95.4 MiB | 0.030 | 0.064 | 0.011 | 20.0 | 0.9 | 0.0 | 19920 | 2.9 |
| ar (`corpus.ar`) | 95.3 MiB | 0.029 | 0.066 | 0.066 | 21.2 | 0.9 | 0.0 | 19285 | 2.2 |
| iso (`corpus.iso`) | 95.7 MiB | 0.027 | 0.064 | 0.064 | 20.5 | 0.9 | 0.0 | 19313 | 2.8 |
| ext4 (`corpus.ext4`) | 152.0 MiB | 0.007 | 0.011 | 0.011 | 18.2 | 1.0 | 0.0 | 2545 | 2.5 |
| mbr/ext4 (`corpus-mbr.img`) | 153.0 MiB | 0.007 | 0.011 | 0.011 | 18.7 | 1.0 | 0.0 | 2918 | 2.8 |
| qcow2/ext4 (`corpus.qcow2`) | 96.4 MiB | 0.007 | 0.011 | 0.011 | 18.6 | 1.0 | 0.0 | 2503 | 2.7 |
| safetensors (`model.safetensors`) | 64.0 MiB | 0.026 | 0.064 | 0.011 | 21.3 | 0.9 | 0.0 | 7408 | 4.1 |
| gguf (`model.gguf`) | 64.0 MiB | 0.025 | 0.064 | 0.011 | 21.2 | 0.9 | 0.0 | 6888 | 4.4 |
| nested-tar (`nested.tar`) | 136.6 MiB | 0.100 | 0.124 | 0.124 | 29.8 | 0.9 | 0.1 | 19682 | 4.3 |
| 7z (`corpus.7z`) | 68.0 MiB | 0.028 | 0.064 | 0.064 | 20.4 | 91.8 | 2.4 | 19180 | 2.7 |
| squashfs (`corpus.squashfs`) | 68.2 MiB | 0.008 | 0.012 | 0.011 | 18.2 | 1.1 | 0.0 | 2570 | 2.8 |
| fat (`corpus.fat`) | 152.0 MiB | 0.007 | 0.012 | 0.011 | 17.8 | 1.9 | 0.0 | 624 | 2.8 |
| exfat (`corpus.exfat`) | 152.0 MiB | 0.007 | 0.011 | 0.011 | 18.1 | 0.9 | 0.0 | 1681 | 2.8 |

## Skipped / errors

| Fixture | Metric | Status | Reason / producer |
|---|---|---|---|
| — | — | — | None |

## Methodology and caveats

- Rust binary only. Each cold index uses `-f --no-mount -c --index-file … --index-minimum-file-count 0`; cold/warm foreground mounts rebuild/reuse the same index. Nested TAR uses `-r`.
- Cold means index recreation, not a flushed OS page cache. One cold index and one cold/warm mount per fixture. Mount readiness includes polling and a successful directory listing; VmHWM is sampled immediately after readiness (unavailable values are skips).
- Read metrics run on the warm mount: seeded random cat, median of 15 (32 KiB members, 64 KiB tensors for models); 15 exact 64 KiB os.pread calls on one open bandwidth member; median of 3 full cat bandwidth samples. Find is one walk after reads. SHA-256 verifies the bandwidth member after sequential reads.
- Regular-file membership is checked before reads: corpus count + blob; twice that for nested ZIP+tar.gz; models include 48 tensor JSON sidecars, metadata JSON, and safetensors raw-header JSON (98/97 files). Filesystem bookkeeping directories do not add regular members.
- Model bandwidth uses layer/47/weight (8 MiB), nested bandwidth uses corpus.zip/blob.bin, partition images use p1/blob.bin. Producer details are in CSV notes. Missing producer tools are skips; producer/daemon/read/count/checksum failures are errors.
- FUSE plus page cache is not disk speed. This is a single-host directional comparison; process startup and cached reads dominate small timings. Build profile, load, compression layout, temporary storage and fixture size matter. No Python ratarmount baseline is involved.
