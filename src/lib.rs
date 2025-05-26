//! [Netlink](https://www.man7.org/linux/man-pages/man7/netlink.7.html) `NETLINK_KOBJECT_UEVENT`
//! packet parser.
//!
//! The [uevents](https://www.kernel.org/doc/html/latest/core-api/kobject.html#uevents) are
//! triggered by `kobject_uevent` and `kobject_uevent_env` to signal a change in the referred
//! kobject.

use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    io,
    path::{Path, PathBuf},
    str::{self, FromStr},
};

use compact_str::{CompactString, ToCompactString};

#[derive(Debug, ::thiserror::Error)]
pub enum Error {
    #[error("Unexpected ACTION: {0:?}")]
    UnexpectedAction(CompactString),
    #[error("Unexpected SEQNUM: {0:?}")]
    InvalidSeqNum(CompactString),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("path is not under sysfs root mountpoint")]
    NotUnderSysfs,
    #[error("packet is not valid UTF-8")]
    InvalidUtf8,
    #[error("ACTION not found")]
    ActionNotFound,
    #[error("DEVPATH not found")]
    DevPathNotFound,
    #[error("SUBSYSTEM not found")]
    SubsystemNotFound,
    #[error("SEQNUM missing")]
    SeqMissing,
}

/// All possible `kobject` actions.
///
/// See [`include/linux/kobject.h`][1] (and [`lib/kobject_uevent.c`][2] regarding its parsing).
///
/// [1]: https://elixir.bootlin.com/linux/v6.15/source/include/linux/kobject.h#L43-L62
/// [2]: https://elixir.bootlin.com/linux/v6.15/source/lib/kobject_uevent.c#L49-L59
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Action {
    /// A new kobject is added.
    Add,
    /// A kobject is removed.
    Remove,
    /// The kobject changed its internal state.
    ///
    /// The `env` contains kobject-specific information.
    Change,
    /// The kobject is reparented as a result of `kobject_move`.
    ///
    /// The `env` contains `DEVPATH_OLD=<oldpath>`.
    Move,
    /// The device is back online after successful `device_offline`.
    Online,
    /// The device is ready to be hot-removed.
    Offline,
    /// The device is bound to a driver.
    Bind,
    /// The device is not bound to its driver anymore.
    Unbind,
}

impl FromStr for Action {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "add" => Action::Add,
            "remove" => Action::Remove,
            "change" => Action::Change,
            "move" => Action::Move,
            "online" => Action::Online,
            "offline" => Action::Offline,
            "bind" => Action::Bind,
            "unbind" => Action::Unbind,
            _ => Err(Error::UnexpectedAction(s.to_compact_string()))?,
        })
    }
}

/// Linux kernel userspace event.
#[derive(Debug, Clone, Eq)]
pub struct UEvent<S: BuildHasher = RandomState> {
    /// Action happening
    pub action: Action,
    /// Complete kobject path
    pub devpath: PathBuf,
    /// Origin subsystem of the event
    pub subsystem: CompactString,
    /// Miscellaneous arguments
    pub env: HashMap<CompactString, CompactString, S>,
    /// Sequence number
    pub seq: u64,
}

impl<S: BuildHasher> PartialEq for UEvent<S> {
    fn eq(&self, other: &Self) -> bool {
        self.action.eq(&other.action)
            && self.seq.eq(&other.seq)
            && self.subsystem.eq(&other.subsystem)
            && self.devpath.eq(&other.devpath)
            && self.env.eq(&other.env)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MaybeUEvent<S: BuildHasher = RandomState> {
    /// Action happening
    pub action: Option<Action>,
    /// Complete Kernel Object path
    pub devpath: Option<PathBuf>,
    /// SubSystem originating the event
    pub subsystem: Option<CompactString>,
    /// Arguments
    pub env: HashMap<CompactString, CompactString, S>,
    /// Sequence number
    pub seq: Option<u64>,
}

/// Parse `key=value` strings as [`UEvent`]. Some fields may be missing.
fn parse_uevent_iter<'a>(iter: impl Iterator<Item = &'a str>) -> Result<MaybeUEvent, Error> {
    let mut ret = MaybeUEvent::default();

    for f in iter {
        if let Some((key, value)) = f.split_once('=') {
            match key {
                "ACTION" => ret.action = Some(value.parse::<Action>()?),
                "DEVPATH" => {
                    ret.devpath = Some(value.parse().expect("PathBuf::from_str is infallible"))
                }
                "SUBSYSTEM" => ret.subsystem = Some(value.to_compact_string()),
                "SEQNUM" => {
                    ret.seq = Some(
                        value
                            .parse::<u64>()
                            .map_err(|_| Error::InvalidSeqNum(value.to_compact_string()))?,
                    )
                }
                _ => {
                    _ = ret
                        .env
                        .insert(key.to_compact_string(), value.to_compact_string())
                }
            }
        }
    }

    Ok(ret)
}

impl UEvent {
    /// Parse a `sysfs(5)` path as an [`Action::Add`] [`UEvent`].
    pub fn from_sysfs_path(
        path: impl AsRef<Path>,
        sysfs_root: impl AsRef<Path>,
    ) -> Result<UEvent, Error> {
        let path = path.as_ref();
        let uevent = ::std::fs::read_to_string(path.join("uevent"))?;
        let subsystem_path = ::std::fs::read_link(path.join("subsystem"))?;
        let lines = uevent.lines();

        let MaybeUEvent { env, .. } = parse_uevent_iter(lines)?;

        // make it look like a netlink devpath
        let devpath = Path::new("/").join(
            path.canonicalize()?
                .strip_prefix(sysfs_root)
                .map_err(|_| Error::NotUnderSysfs)?,
        );
        let subsystem = subsystem_path
            .file_name()
            .ok_or(Error::SubsystemNotFound)?
            .to_string_lossy()
            .to_compact_string();

        Ok(UEvent {
            action: Action::Add,
            devpath,
            subsystem,
            env,
            seq: 0,
        })
    }

    /// Parse a netlink packet as received from the `NETLINK_KOBJECT_UEVENT` broadcast.
    pub fn from_netlink_packet(pkt: &[u8]) -> Result<UEvent, Error> {
        let lines = str::from_utf8(pkt)
            .map_err(|_| Error::InvalidUtf8)?
            .split('\0');
        let MaybeUEvent {
            action,
            devpath,
            subsystem,
            env,
            seq,
        } = parse_uevent_iter(lines)?;

        Ok(UEvent {
            action: action.ok_or(Error::ActionNotFound)?,
            devpath: devpath.ok_or(Error::DevPathNotFound)?,
            subsystem: subsystem.ok_or(Error::SubsystemNotFound)?,
            env,
            seq: seq.ok_or(Error::SeqMissing)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! uevent {
        (
            action: $action:expr,
             devpath: $devpath:expr,
             subsystem: $subsystem:expr,
             env: { $($env_name:expr => $env_value:expr),* $(,)? },
             seq: $seq:expr
         ) => {
            UEvent {
                action: $action,
                devpath: PathBuf::from($devpath),
                subsystem: $subsystem.to_compact_string(),
                env: IntoIterator::into_iter([
                    $(($env_name.to_compact_string(), $env_value.to_compact_string())),*
                ]).collect(),
                seq: $seq,
            }
        };
    }

    #[test]
    fn add_uevent() {
        const DATA: &[u8] = b"add@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=add\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3469";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Add,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "add",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3469",
                },
                seq: 3469
            }
        );
    }

    #[test]
    fn remove_uevent() {
        const DATA: &[u8] = b"remove@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=remove\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3471";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Remove,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "remove",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3471",
                },
                seq: 3471
            }
        );
    }

    #[test]
    fn change_uevent() {
        const DATA: &[u8] = b"change@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=change\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3472";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Change,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "change",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3472",
                },
                seq: 3472
            }
        );
    }

    #[test]
    fn move_uevent() {
        const DATA: &[u8] = b"move@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=move\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3473";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Move,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "move",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3473",
                },
                seq: 3473
            }
        );
    }

    #[test]
    fn online_uevent() {
        const DATA: &[u8] = b"online@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=online\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3474";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Online,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "online",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3474",
                },
                seq: 3474
            }
        );
    }

    #[test]
    fn offline_uevent() {
        const DATA: &[u8] = b"offline@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=offline\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3475";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Offline,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "offline",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3475",
                },
                seq: 3475
            }
        );
    }

    #[test]
    fn bind_uevent() {
        const DATA: &[u8] = b"bind@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=bind\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3476";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Bind,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "bind",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3476",
                },
                seq: 3476
            }
        );
    }

    #[test]
    fn unbind_uevent() {
        const DATA: &[u8] = b"unbind@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=unbind\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SYNTH_UUID=0\0\
                              MAJOR=4\0\
                              MINOR=70\0\
                              DEVNAME=ttyS6\0\
                              SEQNUM=3477";
        assert_eq!(
            UEvent::from_netlink_packet(DATA).unwrap(),
            uevent! {
                action: Action::Unbind,
                devpath: "/devices/platform/serial8250/tty/ttyS6",
                subsystem: "tty",
                env: {
                    //"ACTION" => "unbind",
                    //"DEVPATH" => "/devices/platform/serial8250/tty/ttyS6",
                    //"SUBSYSTEM" => "tty",
                    "SYNTH_UUID" => "0",
                    "MAJOR" => "4",
                    "MINOR" => "70",
                    "DEVNAME" => "ttyS6",
                    //"SEQNUM" => "3477",
                },
                seq: 3477
            }
        );
    }

    #[test]
    fn invalid_event() {
        const DATA: &[u8] = b"hello@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=hello\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SEQNUM=3477";
        assert!(UEvent::from_netlink_packet(DATA).is_err());
    }

    #[test]
    fn missing_action() {
        const DATA: &[u8] = b"add@/devices/platform/serial8250/tty/ttyS6\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty\0\
                              SEQNUM=3477";
        assert!(UEvent::from_netlink_packet(DATA).is_err());
    }

    #[test]
    fn missing_devpath() {
        const DATA: &[u8] = b"add@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=unbind\0\
                              SUBSYSTEM=tty\0\
                              SEQNUM=3477";
        assert!(UEvent::from_netlink_packet(DATA).is_err());
    }

    #[test]
    fn missing_subsystem() {
        const DATA: &[u8] = b"add@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=unbind\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SEQNUM=3477";
        assert!(UEvent::from_netlink_packet(DATA).is_err());
    }

    #[test]
    fn missing_seqnum() {
        const DATA: &[u8] = b"add@/devices/platform/serial8250/tty/ttyS6\0\
                              ACTION=unbind\0\
                              DEVPATH=/devices/platform/serial8250/tty/ttyS6\0\
                              SUBSYSTEM=tty";
        assert!(UEvent::from_netlink_packet(DATA).is_err());
    }
}
