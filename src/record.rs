use std::{
    collections::{btree_set, BTreeSet},
    convert::TryFrom,
    fmt,
    net::{self, Ipv4Addr, Ipv6Addr},
    str::{self, FromStr},
    string::FromUtf8Error,
};

use trust_dns_client::rr::{self, rdata};

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

    pub fn name(&self) -> &rr::Name {
        &self.name
    }

    pub fn dns_class(&self) -> rr::DNSClass {
        self.dns_class
    }

    pub fn record_type(&self) -> rr::RecordType {
        self.data.record_type()
    }

    pub fn to_rrset(&self, ttl: u32) -> rr::RecordSet {
        let mut rrset = rr::RecordSet::with_ttl(self.name.clone(), self.record_type(), ttl);
        for data in self.iter_data() {
            rrset.add_rdata(data);
        }
        rrset
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

    pub fn contains(&self, entry: &rr::RData) -> bool {
        match (&self.data, entry) {
            (RsData::TXT(txts), rr::RData::TXT(txt)) => {
                if let Ok(txt) = txt_string(txt) {
                    txts.contains(&txt)
                } else {
                    false
                }
            }
            (RsData::A(addrs), rr::RData::A(addr)) => addrs.contains(addr),
            (RsData::AAAA(addrs), rr::RData::AAAA(addr)) => addrs.contains(addr),
            _ => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        match &self.data {
            RsData::TXT(txts) => txts.is_empty(),
            RsData::A(addrs) => addrs.is_empty(),
            RsData::AAAA(addrs) => addrs.is_empty(),
        }
    }

    pub fn is_subset(&self, other: &RecordSet) -> bool {
        use RsData::*;
        if self.name() != other.name() {
            return false;
        }
        match (&self.data, &other.data) {
            (TXT(txts), TXT(other_txts)) => txts.is_subset(other_txts),
            (A(addrs), A(other_addrs)) => addrs.is_subset(other_addrs),
            (AAAA(addrs), AAAA(other_addrs)) => addrs.is_subset(other_addrs),
            _ => false,
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
            A(iter) => iter.next().map(|item| rr::RData::A(rr::rdata::A(*item))),
            AAAA(iter) => iter
                .next()
                .map(|item| rr::RData::AAAA(rr::rdata::AAAA(*item))),
            TXT(iter) => iter
                .next()
                .map(|item| rr::RData::TXT(rdata::TXT::new(vec![item.into()]))),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
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

impl RsData {
    pub fn record_type(&self) -> rr::RecordType {
        match self {
            RsData::TXT(_) => rr::RecordType::TXT,
            RsData::A(_) => rr::RecordType::A,
            RsData::AAAA(_) => rr::RecordType::AAAA,
        }
    }
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
        if parts.len() == 1 {
            return match parts[0].to_uppercase().as_str() {
                "TXT" => Ok(RsData::TXT(Default::default())),
                "A" => Ok(RsData::A(Default::default())),
                "AAAA" => Ok(RsData::AAAA(Default::default())),
                _ => Err(RsDataParseError::UnknownType),
            };
        }
        if parts.len() != 2 {
            return Err(RsDataParseError::MissingType);
        }
        let (rtype, rdata) = (parts[0].to_uppercase(), parts[1]);
        let rdata_parts = rdata.split(',');
        match rtype.as_str() {
            "TXT" => Ok(RsData::TXT(rdata_parts.map(|s| s.to_owned()).collect())),
            "A" => {
                let addrs = rdata_parts
                    .map(|part| part.parse().map_err(RsDataParseError::Addr))
                    .collect::<Result<_, _>>()?;
                Ok(RsData::A(addrs))
            }
            "AAAA" => {
                let addrs = rdata_parts
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

fn txt_string(txt: &rdata::TXT) -> Result<String, TryFromRecordsError> {
    let data = txt.txt_data();
    if data.len() != 1 {
        return Err(TryFromRecordsError::UnsupportedTxtValue);
    }
    str::from_utf8(&data[0])
        .map(Into::into)
        .map_err(TryFromRecordsError::Utf8)
}

impl TryFrom<&[rr::Record]> for RecordSet {
    type Error = TryFromRecordsError;

    fn try_from(rrs: &[rr::Record]) -> Result<Self, Self::Error> {
        let keys: BTreeSet<RsKey> = rrs.iter().map(Into::into).collect();
        match keys.len() {
            0 => Err(TryFromRecordsError::Empty),
            1 => {
                let key = keys.iter().next().unwrap();
                let data = match key.record_type {
                    rr::RecordType::A => RsData::A(
                        rrs.iter()
                            .filter_map(|rr| Some(rr.data()?.as_a()?.0))
                            .collect(),
                    ),
                    rr::RecordType::AAAA => RsData::AAAA(
                        rrs.iter()
                            .filter_map(|rr| Some(rr.data()?.as_aaaa()?.0))
                            .collect(),
                    ),
                    rr::RecordType::TXT => RsData::TXT(
                        rrs.iter()
                            .filter_map(|rr| Some(txt_string(rr.data()?.as_txt()?)))
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
    UnsupportedTxtValue,
    FromUtf8(FromUtf8Error),
    Utf8(str::Utf8Error),
}

impl fmt::Display for TryFromRecordsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TryFromRecordsError::*;
        match self {
            Empty => write!(f, "no records"),
            MultipleKeys(_) => write!(f, "multiple keys"),
            UnsupportedType(rtype) => write!(f, "unsupported record type {}", rtype),
            UnsupportedTxtValue => write!(f, "unsupported TXT value"),
            Utf8(e) => write!(f, "non-UTF8 content: {}", e),
            FromUtf8(e) => write!(f, "non-UTF8 content: {}", e),
        }
    }
}

impl std::error::Error for TryFromRecordsError {}
