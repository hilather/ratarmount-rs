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
}
