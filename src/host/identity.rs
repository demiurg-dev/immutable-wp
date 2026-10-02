/// Host identity of a site's container: fixed UID/GID range and SELinux MCS categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    /// Host UID/GID that container UID/GID 0 maps to (range of 65536).
    pub base_id: u32,
    /// Host UID/GID of container www-data (33).
    pub www_uid: u32,
    pub mcs: (u32, u32),
}

impl Identity {
    /// `id` and `id_offset` must be validated (`validate_site` / `validate_global`) beforehand.
    pub fn for_site(id: u32, id_offset: u32) -> Self {
        let base_id = id
            .checked_mul(65_536)
            .and_then(|n| n.checked_add(id_offset))
            .filter(|b| b.checked_add(65_536).is_some())
            .expect("id/id_offset overflow; validate_global and validate_site must run first");
        Self {
            base_id,
            www_uid: base_id + 33,
            mcs: (id, id + 512),
        }
    }

    pub fn selinux_level(&self) -> String {
        format!("s0:c{},c{}", self.mcs.0, self.mcs.1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acme_slot_3() {
        let i = Identity::for_site(3, 100_000);
        assert_eq!(i.base_id, 296_608);
        assert_eq!(i.www_uid, 296_641);
        assert_eq!(i.mcs, (3, 515));
        assert_eq!(i.selinux_level(), "s0:c3,c515");
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn overflowing_offset_panics_instead_of_wrapping() {
        Identity::for_site(511, u32::MAX - 65_536);
    }

    #[test]
    fn slots_never_overlap() {
        for id in 1..511 {
            let a = Identity::for_site(id, 100_000);
            let b = Identity::for_site(id + 1, 100_000);
            assert_eq!(a.base_id + 65_536, b.base_id);
            assert_ne!(a.mcs.1, b.mcs.0);
        }
        assert!(
            Identity::for_site(511, 100_000)
                .base_id
                .checked_add(65_536)
                .is_some()
        );
    }
}
