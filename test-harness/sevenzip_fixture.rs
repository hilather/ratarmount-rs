// Shared test-only 7z fixture. Included by test targets, never production code.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

/// Copy-coder 7z written without an external `7z`: one solid folder holding
/// every member (`solid`), or one folder per member (`7z a -ms=off`).
/// Test fixture for small members (sizes below 128 bytes); not an archive writer.
pub fn copy_7z_fixture(members: &[(&str, &[u8])], solid: bool) -> Vec<u8> {
    let n = members.len() as u8;
    let size = |b: &[u8]| {
        assert!(b.len() < 0x80, "single-byte 7z numbers only");
        b.len() as u8
    };
    let payload: Vec<u8> = members.iter().flat_map(|(_, b)| b.to_vec()).collect();
    let mut header = vec![1, 4, 6, 0];
    if solid {
        let total = size(&payload);
        header.extend_from_slice(&[1, 9, total, 0]);
        header.extend_from_slice(&[7, 11, 1, 0, 1, 1, 0, 12, total, 0]);
        header.extend_from_slice(&[8, 13, n, 9]);
        header.extend(members[..members.len() - 1].iter().map(|(_, b)| size(b)));
        header.push(0);
    } else {
        header.extend_from_slice(&[n, 9]);
        header.extend(members.iter().map(|(_, b)| size(b)));
        header.extend_from_slice(&[0, 7, 11, n, 0]);
        for _ in members {
            header.extend_from_slice(&[1, 1, 0]);
        }
        header.push(12);
        header.extend(members.iter().map(|(_, b)| size(b)));
        header.push(0);
    }
    header.push(0);
    let mut names = vec![0u8];
    for (name, _) in members {
        for unit in name.encode_utf16().chain([0]) {
            names.extend_from_slice(&unit.to_le_bytes());
        }
    }
    header.extend_from_slice(&[5, n, 17, size(&names)]);
    header.extend(names);
    header.extend_from_slice(&[0, 0]);
    let mut start = (payload.len() as u64).to_le_bytes().to_vec();
    start.extend_from_slice(&(header.len() as u64).to_le_bytes());
    start.extend_from_slice(&crc32(&header).to_le_bytes());
    let mut bytes = b"7z\xbc\xaf\x27\x1c".to_vec();
    bytes.extend_from_slice(&[0, 4]);
    bytes.extend_from_slice(&crc32(&start).to_le_bytes());
    bytes.extend(start);
    bytes.extend(payload);
    bytes.extend(header);
    bytes
}
