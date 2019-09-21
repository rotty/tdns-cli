use std::{
    collections::{btree_set, BTreeSet},
    convert::TryFrom,
    fmt,
    net::{self, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    string::FromUtf8Error,
};

use trust_dns::rr::{self, rdata};

/// This is a representation of the record set as described in RFC 2136.
///
/// A domain name identifies a node within the domain name space tree structure.
/// Each node has a set (possibly empty) of Resource Records (RRs).  All RRs
/// having the same NAME, CLASS and TYPE are called a Resource Record Set (RRset
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecordSet {
    name: rr::Name,
    dns_class: rr::DNSClass,
    data: RsData,
}

impl RecordSet {
    pub fn new(name: rr::Name, data: RsData) -> Self {
        RecordSet {
            name,
            dns_class: rr::DNSClass::IN,
            data,
        }
    }

    pub fn dns_class(&self) -> rr::DNSClass {
        self.dns_class
    }

    pub fn record_type(&self) -> rr::RecordType {
        match self.data {
            RsData::TXT(_) => rr::RecordType::TXT,
            RsData::A(_) => rr::RecordType::A,
            RsData::AAAA(_) => rr::RecordType::AAAA,
        }
    }

    pub fn data(&self) -> &RsData {
        &self.data
    }

    pub fn iter_data(&self) -> RsDataIter {
        let inner = match &self.data {
            RsData::TXT(txts) => RsDataIterInner::TXT(txts.iter()),
            RsData::A(addrs) => RsDataIterInner::A(addrs.iter()),
            RsData::AAAA(addrs) => RsDataIterInner::AAAA(addrs.iter()),
        };
        RsDataIter(inner)
    }

    pub fn satisfied_by(&self, rrs: &[rr::Record]) -> bool {
        match RecordSet::try_from(rrs) {
            Err(_) => false,
            Ok(rs) => self == &rs,
        }
    }
}

impl fmt::Display for RecordSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.data)
    }
}

#[derive(Debug)]
pub struct RsDataIter<'a>(RsDataIterInner<'a>);

impl<'a> Iterator for RsDataIter<'a> {
    type Item = rr::RData;

    fn next(&mut self) -> Option<Self::Item> {
        use RsDataIterInner::*;
        match &mut self.0 {
            A(iter) => iter.next().map(|item| rr::RData::A(*item)),
            AAAA(iter) => iter.next().map(|item| rr::RData::AAAA(*item)),
            TXT(iter) => iter
                .next()
                .map(|item| rr::RData::TXT(rdata::TXT::new(vec![item.into()]))),
        }
    }
}

#[derive(Debug)]
enum RsDataIterInner<'a> {
    TXT(btree_set::Iter<'a, String>),
    A(btree_set::Iter<'a, Ipv4Addr>),
    AAAA(btree_set::Iter<'a, Ipv6Addr>),
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum RsData {
    TXT(BTreeSet<String>), // TODO: simplified, only single value for now.
    A(BTreeSet<Ipv4Addr>),
    AAAA(BTreeSet<Ipv6Addr>),
}

impl fmt::Display for RsData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // FIXME: DRY
        match self {
            RsData::A(addrs) => {
                write!(f, "A:")?;
                for (i, addr) in addrs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", addr)?;
                }
            }
            RsData::AAAA(addrs) => {
                write!(f, "A:")?;
                for (i, addr) in addrs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", addr)?;
                }
            }
            RsData::TXT(txts) => {
                write!(f, "TXT:")?;
                for (i, txt) in txts.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", txt)?;
                }
            }
        }
        Ok(())
    }
}

impl FromStr for RsData {
    type Err = RsDataParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(RsDataParseError::MissingType);
        }
        let (rtype, rdata) = (parts[0].to_uppercase(), parts[1]);
        let rdata_parts = rdata.split(',');
        match rtype.as_str() {
            "TXT" => Ok(RsData::TXT(
                rdata_parts.into_iter().map(|s| s.to_owned()).collect(),
            )),
            "A" => {
                let addrs = rdata_parts
                    .into_iter()
                    .map(|part| part.parse().map_err(RsDataParseError::Addr))
                    .collect::<Result<_, _>>()?;
                Ok(RsData::A(addrs))
            }
            "AAAA" => {
                let addrs = rdata_parts
                    .into_iter()
                    .map(|part| part.parse().map_err(RsDataParseError::Addr))
                    .collect::<Result<_, _>>()?;
                Ok(RsData::AAAA(addrs))
            }
            _ => Err(RsDataParseError::UnknownType),
        }
    }
}

#[derive(Debug)]
pub enum RsDataParseError {
    MissingType,
    UnknownType,
    Addr(net::AddrParseError),
}

impl fmt::Display for RsDataParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use RsDataParseError::*;
        match self {
            MissingType => write!(f, "missing type"),
            UnknownType => write!(f, "unknown type"),
            Addr(e) => write!(f, "invalid address: {}", e),
        }
    }
}

impl std::error::Error for RsDataParseError {}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RsKey {
    name: rr::Name,
    dns_class: rr::DNSClass,
    record_type: rr::RecordType,
}

impl RsKey {
    pub fn name(&self) -> &rr::Name {
        &self.name
    }
    pub fn dns_class(&self) -> rr::DNSClass {
        self.dns_class
    }
    pub fn record_type(&self) -> rr::RecordType {
        self.record_type
    }
}

impl From<&rr::Record> for RsKey {
    fn from(rr: &rr::Record) -> Self {
        RsKey {
            name: rr.name().clone(),
            dns_class: rr.dns_class(),
            record_type: rr.record_type(),
        }
    }
}

impl TryFrom<&[rr::Record]> for RecordSet {
    type Error = TryFromRecordsError;

    fn try_from(rrs: &[rr::Record]) -> Result<Self, Self::Error> {
        fn txt_string(_txt: &rdata::TXT) -> Result<String, TryFromRecordsError> {
            Err(TryFromRecordsError::UnsupportedType(rr::RecordType::TXT))
        }
        let keys: BTreeSet<RsKey> = rrs.iter().map(Into::into).collect();
        match keys.len() {
            0 => Err(TryFromRecordsError::Empty),
            1 => {
                let key = keys.iter().nth(0).unwrap();
                // TODO: I'm not sure if `trust-dns` actually guarantees that
                // these `unwrap` calls never panic, but I'd guess so. I should
                // study its code and submit a documentation patch to clarify
                // behavior in either case.
                let data = match key.record_type {
                    rr::RecordType::A => RsData::A(
                        rrs.iter()
                            .map(|rr| rr.rdata().as_a().unwrap().clone())
                            .collect(),
                    ),
                    rr::RecordType::AAAA => RsData::AAAA(
                        rrs.iter()
                            .map(|rr| rr.rdata().as_aaaa().unwrap().clone())
                            .collect(),
                    ),
                    rr::RecordType::TXT => RsData::TXT(
                        rrs.iter()
                            .map(|rr| txt_string(rr.rdata().as_txt().unwrap()))
                            .collect::<Result<_, _>>()?,
                    ),
                    rtype => return Err(TryFromRecordsError::UnsupportedType(rtype)),
                };
                Ok(RecordSet {
                    name: key.name.clone(),
                    dns_class: key.dns_class,
                    data,
                })
            }
            _ => Err(TryFromRecordsError::MultipleKeys(keys)),
        }
    }
}

#[derive(Debug)]
pub enum TryFromRecordsError {
    Empty,
    MultipleKeys(BTreeSet<RsKey>),
    UnsupportedType(rr::RecordType),
    FromUtf8(FromUtf8Error),
}

impl fmt::Display for TryFromRecordsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TryFromRecordsError::*;
        match self {
            Empty => write!(f, "no records"),
            MultipleKeys(_) => write!(f, "multiple keys"),
            UnsupportedType(rtype) => write!(f, "unsupported record type {}", rtype),
            FromUtf8(e) => write!(f, "non-UTF8 content: {}", e),
        }
    }
}

impl std::error::Error for TryFromRecordsError {}
