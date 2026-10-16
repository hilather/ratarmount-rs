//! Regression: concurrent large member opens cannot multiply retained RAM caps.
use std::io::{Read, Write};
use std::sync::{Arc, Barrier};

use ratarmount_core::budget::MemoryBudget;
use ratarmount_session::{IndexPolicy, OpenRequest, ReadRequest, Recreate, Session, SourceSpec};

// Minimal Deflate ZIP fixture, using the gzip trailer's IEEE CRC without adding
// a ZIP writer dependency to the binary crate's test graph.
fn zip_fixture(path: &std::path::Path) {
    let mut zip = Vec::new();
    let mut central = Vec::new();
    for index in 0..8u8 {
        let bytes = vec![index + 1; 4 * 1024 * 1024];
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&bytes).unwrap();
        let gzip = encoder.finish().unwrap();
        let compressed = &gzip[10..gzip.len() - 8];
        let crc = &gzip[gzip.len() - 8..gzip.len() - 4];
        let name = format!("member{index}");
        let offset = zip.len() as u32;
        zip.extend_from_slice(b"PK\x03\x04");
        for n in [20u16, 0, 8, 0, 0] {
            zip.extend_from_slice(&n.to_le_bytes());
        }
        zip.extend_from_slice(crc);
        zip.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(name.as_bytes());
        zip.extend_from_slice(compressed);
        central.extend_from_slice(b"PK\x01\x02");
        for n in [20u16, 20, 0, 8, 0, 0] {
            central.extend_from_slice(&n.to_le_bytes());
        }
        central.extend_from_slice(crc);
        central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        central.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        for n in [name.len() as u16, 0, 0, 0, 0] {
            central.extend_from_slice(&n.to_le_bytes());
        }
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let start = zip.len() as u32;
    zip.extend_from_slice(&central);
    zip.extend_from_slice(b"PK\x05\x06");
    for n in [0u16, 0, 8, 8] {
        zip.extend_from_slice(&n.to_le_bytes());
    }
    zip.extend_from_slice(&(central.len() as u32).to_le_bytes());
    zip.extend_from_slice(&start.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    std::fs::write(path, zip).unwrap();
}

#[test]
fn regression_memory_budget_64m_concurrent_session_members() {
    MemoryBudget::install(64 * 1024 * 1024).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.zip");
    zip_fixture(&path);
    let session = Arc::new(
        Session::open(OpenRequest {
            source: SourceSpec::Path(path),
            index: IndexPolicy::Temp,
            explicit_index: None,
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            parallelization: 4.into(),
            recreate: Recreate::IfInvalid,
        })
        .unwrap(),
    );
    let barrier = Arc::new(Barrier::new(8));
    std::thread::scope(|scope| {
        for index in 0..8u8 {
            let session = session.clone();
            let barrier = barrier.clone();
            scope.spawn(move || {
                barrier.wait();
                let mut reader = session
                    .read_range(ReadRequest {
                        path: format!("/member{index}"),
                        offset: 0,
                        max_len: 4 * 1024 * 1024,
                    })
                    .unwrap();
                barrier.wait(); // All readers stay alive, including evicted shared buffers.
                let mut buffer = [0; 65536];
                let mut total = 0;
                loop {
                    let count = reader.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    assert!(buffer[..count].iter().all(|&b| b == index + 1));
                    total += count;
                }
                assert_eq!(total, 4 * 1024 * 1024);
            });
        }
    });
    let snapshot = MemoryBudget::global().snapshot();
    assert!(snapshot.high_water <= 64 * 1024 * 1024);
    assert!(snapshot
        .pools
        .iter()
        .any(|p| p.name == "zip-inflate" && p.high_water > 0));
    assert!(snapshot.pools.iter().all(|p| p.high_water <= p.cap));
    drop(session);
    assert_eq!(MemoryBudget::global().snapshot().reserved, 0);
}
