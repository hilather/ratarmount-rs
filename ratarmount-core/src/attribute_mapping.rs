//! Presentation-only Unix ownership and permission overrides.

/// Applied when building protocol attributes, never when mutating the source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttributeMapping {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub umask: u32,
}

impl AttributeMapping {
    /// Parse the ratarmount-owned options from a FUSE-style option string.
    /// Other options are left to the frontend. Repeated values use the last one.
    pub fn parse(options: &str) -> Result<Self, String> {
        let mut mapping = Self::default();
        for option in options.split(',').map(str::trim) {
            let Some((key, value)) = option.split_once('=') else {
                continue;
            };
            match key {
                "uid" | "gid" => {
                    let id = value
                        .parse::<u32>()
                        .map_err(|_| format!("invalid {key}={value}: expected a numeric ID"))?;
                    if key == "uid" {
                        mapping.uid = Some(id);
                    } else {
                        mapping.gid = Some(id);
                    }
                }
                "umask" => {
                    mapping.umask = u32::from_str_radix(value, 8)
                        .ok()
                        .filter(|mask| *mask <= 0o777)
                        .ok_or_else(|| format!("invalid umask={value}: expected octal 000..777"))?;
                }
                _ => {}
            }
        }
        Ok(mapping)
    }

    pub fn uid(self, uid: u32) -> u32 {
        self.uid.unwrap_or(uid)
    }
    pub fn gid(self, gid: u32) -> u32 {
        self.gid.unwrap_or(gid)
    }
    pub fn mode(self, mode: u32) -> u32 {
        mode & !self.umask
    }

    /// Drop requested owner IDs that equal the owner this entry is already
    /// presented with (`raw_uid` / `raw_gid` after the mapping). A chown to
    /// the shown owner (`cp -p`, `sed -i`, `rsync -a`) is then a no-op, while
    /// a real ownership change is still passed on and refused.
    pub fn drop_presented_owner(
        self,
        raw_uid: u32,
        raw_gid: u32,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> (Option<u32>, Option<u32>) {
        (
            uid.filter(|uid| *uid != self.uid(raw_uid)),
            gid.filter(|gid| *gid != self.gid(raw_gid)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: container ownership and umask must preserve type and special bits.
    #[test]
    fn regression_attribute_mapping_preserves_type_and_unset_owners() {
        let mapping =
            AttributeMapping::parse("allow_other, uid=12345,gid=23456,umask=027").unwrap();
        for mode in [0o107777, 0o047777, 0o127777] {
            assert_eq!(mapping.mode(mode), mode & !0o027);
            assert_eq!(AttributeMapping::default().mode(mode), mode);
        }
        assert_eq!((mapping.uid(1), mapping.gid(2)), (12345, 23456));
        assert_eq!(
            (
                AttributeMapping::default().uid(1),
                AttributeMapping::default().gid(2)
            ),
            (1, 2)
        );
        assert_eq!(AttributeMapping::parse("uid=1,uid=2").unwrap().uid, Some(2));
        for option in [
            "uid=x",
            "gid=-1",
            "uid=4294967296",
            "umask=888",
            "umask=1000",
            "umask=",
        ] {
            assert!(AttributeMapping::parse(option).is_err(), "{option}");
        }
    }

    /// Regression: `cp -p` into a write mount failed with EPERM because a
    /// chown to the owner already shown was refused (#327).
    #[test]
    fn regression_same_owner_chown_is_dropped() {
        let plain = AttributeMapping::default();
        let mapped = AttributeMapping::parse("uid=0,gid=0").unwrap();
        // Unmapped: compare with the raw owner.
        assert_eq!(
            plain.drop_presented_owner(1000, 1000, Some(1000), Some(1000)),
            (None, None)
        );
        assert_eq!(
            plain.drop_presented_owner(1000, 1000, Some(0), Some(1000)),
            (Some(0), None)
        );
        assert_eq!(
            plain.drop_presented_owner(1000, 1000, None, Some(5)),
            (None, Some(5))
        );
        // Mapped: compare with the presented owner, not the stored one.
        assert_eq!(
            mapped.drop_presented_owner(1000, 1000, Some(0), Some(0)),
            (None, None)
        );
        assert_eq!(
            mapped.drop_presented_owner(1000, 1000, Some(1000), None),
            (Some(1000), None)
        );
        let gid_only = AttributeMapping::parse("gid=7").unwrap();
        assert_eq!(
            gid_only.drop_presented_owner(1000, 1000, Some(1000), Some(7)),
            (None, None)
        );
        assert_eq!(
            gid_only.drop_presented_owner(1000, 1000, Some(1000), Some(1000)),
            (None, Some(1000))
        );
    }
}
