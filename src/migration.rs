use crate::{Backup, Ipv4, Mac, Result};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreScope {
    Network,
    DnsOnly,
    MacOnly,
}

pub enum IpDraft {
    Full(Ipv4),
    DnsOnly(Option<Vec<Ipv4Addr>>),
}
impl IpDraft {
    pub fn resolve(self, current: &Ipv4) -> Result<Ipv4> {
        let config = match self {
            Self::Full(config) => config,
            Self::DnsOnly(dns) => Ipv4 {
                dns,
                ..current.clone()
            },
        };
        config.validate()?;
        Ok(config)
    }
}

pub fn restore_inputs(
    profile: Backup,
    scope: RestoreScope,
    include_mac: bool,
) -> Result<(Option<IpDraft>, Option<Mac>)> {
    let require_ip = || -> Result<Ipv4> {
        profile
            .ipv4
            .ok_or_else(|| "File tidak memuat konfigurasi IPv4/DNS.".into())
    };
    let require_mac = || -> Result<Mac> {
        profile
            .mac
            .ok_or_else(|| "File tidak memuat MAC. Gunakan pilihan tanpa MAC.".into())
    };
    match scope {
        RestoreScope::Network => Ok((
            Some(IpDraft::Full(require_ip()?)),
            if include_mac {
                Some(require_mac()?)
            } else {
                None
            },
        )),
        RestoreScope::DnsOnly => Ok((Some(IpDraft::DnsOnly(require_ip()?.dns)), None)),
        RestoreScope::MacOnly => Ok((None, Some(require_mac()?))),
    }
}

pub fn new_static_ips(target: &Ipv4, before: &Ipv4) -> Vec<Ipv4Addr> {
    target
        .addresses
        .iter()
        .map(|a| a.ip)
        .filter(|ip| !before.addresses.iter().any(|a| a.ip == *ip))
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressConflict {
    Ipv4(Ipv4Addr),
    Mac(Mac),
}
pub fn address_conflict(
    requested_ips: &[Ipv4Addr],
    requested_mac: Option<Mac>,
    other_ips: impl Iterator<Item = Ipv4Addr>,
    other_mac: Option<Mac>,
) -> Option<AddressConflict> {
    if let Some(mac) = requested_mac.filter(|m| Some(*m) == other_mac) {
        return Some(AddressConflict::Mac(mac));
    }
    for ip in other_ips {
        if requested_ips.contains(&ip) {
            return Some(AddressConflict::Ipv4(ip));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Address, ipv4_commands};

    fn profile() -> Backup {
        Backup {
            format: 1,
            source_id: String::new(),
            source_name: "PC lama".into(),
            ipv4: Some(Ipv4 {
                dhcp: false,
                addresses: vec![Address {
                    ip: "172.20.95.190".parse().unwrap(),
                    prefix: 16,
                }],
                gateway: Some("172.20.140.15".parse().unwrap()),
                dns: Some(vec![
                    "172.20.140.15".parse().unwrap(),
                    "8.8.8.8".parse().unwrap(),
                ]),
            }),
            mac: Some("B4-2E-99-73-36-B1".parse().unwrap()),
        }
    }

    #[test]
    fn dns_only_keeps_dhcp_or_static_settings_and_never_sets_mac() {
        for mut current in [
            profile().ipv4.unwrap(),
            Ipv4 {
                dhcp: true,
                addresses: vec![],
                gateway: None,
                dns: None,
            },
        ] {
            if !current.dhcp {
                current.addresses[0].ip = "10.0.0.100".parse().unwrap();
                current.gateway = Some("10.0.0.1".parse().unwrap());
                current.dns = None;
            }
            let (draft, mac) = restore_inputs(profile(), RestoreScope::DnsOnly, true).unwrap();
            let target = draft.unwrap().resolve(&current).unwrap();
            assert!(mac.is_none());
            assert_eq!(target.dhcp, current.dhcp);
            assert_eq!(target.addresses, current.addresses);
            assert_eq!(target.gateway, current.gateway);
            assert_eq!(target.dns, profile().ipv4.unwrap().dns);
            assert!(new_static_ips(&target, &current).is_empty());
            let ops = ipv4_commands(&target, Some(&current)).unwrap();
            assert_eq!(ops.len(), 2);
            assert!(ops.iter().all(|cmd| cmd[1] == "dnsservers"));
        }
    }

    #[test]
    fn automatic_dns_and_mac_only_are_explicit() {
        let mut source = profile();
        source.ipv4.as_mut().unwrap().dns = None;
        let (draft, mac) = restore_inputs(source, RestoreScope::DnsOnly, false).unwrap();
        let current = profile().ipv4.unwrap();
        let target = draft.unwrap().resolve(&current).unwrap();
        assert!(mac.is_none() && target.dns.is_none());
        assert_eq!(
            ipv4_commands(&target, Some(&current)).unwrap(),
            vec![vec!["set", "dnsservers", "source=dhcp"]]
        );
        let (draft, mac) = restore_inputs(profile(), RestoreScope::MacOnly, false).unwrap();
        assert!(draft.is_none());
        assert_eq!(mac, profile().mac);
    }

    #[test]
    fn absent_sections_cannot_silently_be_skipped() {
        let mut source = profile();
        source.mac = None;
        assert!(restore_inputs(source.clone(), RestoreScope::Network, true).is_err());
        assert!(restore_inputs(source.clone(), RestoreScope::MacOnly, false).is_err());
        assert!(restore_inputs(source.clone(), RestoreScope::Network, false).is_ok());
        source.ipv4 = None;
        assert!(restore_inputs(source, RestoreScope::DnsOnly, false).is_err());
    }

    #[test]
    fn only_new_ip_values_and_requested_mac_are_conflicts() {
        let old = profile().ipv4.unwrap();
        let ip = "172.20.95.192".parse().unwrap();
        let mut target = old.clone();
        target.addresses[0].prefix = 24;
        target.addresses.push(Address { ip, prefix: 24 });
        let requested = new_static_ips(&target, &old);
        assert_eq!(requested, vec![ip]);
        assert_eq!(
            address_conflict(
                &requested,
                None,
                [old.addresses[0].ip].into_iter(),
                profile().mac
            ),
            None
        );
        assert_eq!(
            address_conflict(&requested, None, [ip].into_iter(), None),
            Some(AddressConflict::Ipv4(ip))
        );
        let mac = profile().mac.unwrap();
        assert_eq!(
            address_conflict(&[], Some(mac), [].into_iter(), Some(mac)),
            Some(AddressConflict::Mac(mac))
        );
    }
}
