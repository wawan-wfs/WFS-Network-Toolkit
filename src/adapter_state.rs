use crate::Mac;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum AdminState {
    Enabled,
    Disabled,
    Testing,
    Unknown,
}

impl AdminState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Enabled => "Diaktifkan",
            Self::Disabled => "Dinonaktifkan",
            Self::Testing => "Sedang diuji",
            Self::Unknown => "Tidak diketahui",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum MediaState {
    Connected,
    Disconnected,
    Unknown,
}

pub fn link_label(up: bool, admin: AdminState, media: MediaState) -> &'static str {
    if up {
        "Link aktif"
    } else if media == MediaState::Disconnected {
        "Link tidak tersambung"
    } else if admin == AdminState::Disabled {
        "Antarmuka dinonaktifkan"
    } else {
        "Link tidak aktif"
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacReadiness {
    Ready,
    DriverNotStarted,
    InterfaceUnavailable,
}

/// The caller must query the selected PnP device and confirm it has no problem.
/// No disconnected path implicitly enables an interface or a PnP device.
pub fn mac_readiness(
    admin: AdminState,
    media: MediaState,
    up: bool,
    driver_started: bool,
) -> MacReadiness {
    if !driver_started {
        MacReadiness::DriverNotStarted
    } else if admin == AdminState::Enabled
        || (!up && media == MediaState::Disconnected && admin != AdminState::Testing)
    {
        MacReadiness::Ready
    } else {
        MacReadiness::InterfaceUnavailable
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacReadback {
    Verified,
    AddressPending,
    LinkPending,
}

pub fn mac_readback(
    expected: Mac,
    active: Option<Mac>,
    link_was_up: bool,
    link_is_up: bool,
) -> MacReadback {
    if active != Some(expected) {
        MacReadback::AddressPending
    } else if link_was_up && !link_is_up {
        MacReadback::LinkPending
    } else {
        MacReadback::Verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnected_ethernet_with_started_driver_can_set_mac() {
        for admin in [
            AdminState::Enabled,
            AdminState::Disabled,
            AdminState::Unknown,
        ] {
            assert_eq!(
                mac_readiness(admin, MediaState::Disconnected, false, true),
                MacReadiness::Ready
            );
            assert_eq!(
                mac_readiness(admin, MediaState::Disconnected, false, false),
                MacReadiness::DriverNotStarted
            );
        }
    }

    #[test]
    fn uncertain_or_testing_interfaces_are_not_overridden() {
        assert_eq!(
            mac_readiness(AdminState::Disabled, MediaState::Unknown, false, true),
            MacReadiness::InterfaceUnavailable
        );
        assert_eq!(
            mac_readiness(AdminState::Testing, MediaState::Disconnected, false, true),
            MacReadiness::InterfaceUnavailable
        );
        assert_eq!(
            mac_readiness(AdminState::Disabled, MediaState::Connected, false, true),
            MacReadiness::InterfaceUnavailable
        );
        assert_eq!(
            mac_readiness(AdminState::Enabled, MediaState::Connected, true, true),
            MacReadiness::Ready
        );
    }

    #[test]
    fn verifies_exact_mac_while_offline_but_requires_existing_link_to_return() {
        let target = "00-11-22-33-44-55".parse().unwrap();
        let other = "02-11-22-33-44-55".parse().unwrap();
        assert_eq!(
            mac_readback(target, Some(target), false, false),
            MacReadback::Verified
        );
        assert_eq!(
            mac_readback(target, Some(target), true, false),
            MacReadback::LinkPending
        );
        assert_eq!(
            mac_readback(target, Some(target), true, true),
            MacReadback::Verified
        );
        assert_eq!(
            mac_readback(target, Some(other), false, false),
            MacReadback::AddressPending
        );
    }
}
