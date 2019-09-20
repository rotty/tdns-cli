use std::{
    collections::BTreeSet,
    convert::TryFrom,
    fmt,
    iter::FromIterator,
    net::{self, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    string::FromUtf8Error,
};

use trust_dns::rr;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecordSet(BTreeSet<Data>);

impl RecordSet {
    pub fn to_record_types(&self) -> Vec<rr::RecordType> {
        self.0.iter().map(Data::to_record_type).collect()
    }

    pub fn satisfied_by(&self, rrs: &[rr::Record]) -> bool {
        rrs.iter()
            .map(|rr| Data::try_from(rr.rdata()))
            .collect::<Result<Vec<_>, _>>()
            .ok()
            .map(|items| self == &RecordSet::from_iter(items))
            .unwrap_or(false)
    }
}

impl fmt::Display for RecordSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        for (i, item) in self.0.iter().enumerate() {
            if i + 1 < self.0.len() {
                write!(f, "{}, ", item)?;
            } else {
                write!(f, "{}", item)?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl FromIterator<Data> for RecordSet {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Data>,
    {
        RecordSet(iter.into_iter().collect())
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Data {
    // Simplified representation, containing only a single part.
    TXT(String),
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
}

impl Data {
    fn to_record_type(&self) -> rr::RecordType {
        use rr::RecordType;
        match self {
            Data::TXT(_) => RecordType::TXT,
            Data::A(_) => RecordType::A,
            Data::AAAA(_) => RecordType::AAAA,
        }
    }
}

impl TryFrom<&rr::RData> for Data {
    type Error = TryFromRDataError;

    fn try_from(rdata: &rr::RData) -> Result<Self, Self::Error> {
        match rdata {
            rr::RData::A(addr) => Ok(Data::A(*addr)),
            rr::RData::AAAA(addr) => Ok(Data::AAAA(*addr)),
            rr::RData::TXT(txt) => Ok(Data::TXT(
                txt.txt_data()
                    .iter()
                    .map(|item| {
                        String::from_utf8(item.to_vec()).map_err(TryFromRDataError::FromUtf8)
                    })
                    .collect::<Result<_, _>>()?,
            )),
            _ => Err(TryFromRDataError::UnsupportedType(rdata.to_record_type())),
        }
    }
}

#[derive(Debug)]
pub enum TryFromRDataError {
    UnsupportedType(rr::RecordType),
    FromUtf8(FromUtf8Error),
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Data::TXT(content) => {
                if content.chars().any(char::is_whitespace) {
                    write!(f, "TXT:'{}'", content)
                } else {
                    write!(f, "TXT:{}", content)
                }
            }
            Data::A(addr) => write!(f, "A:{}", addr),
            Data::AAAA(addr) => write!(f, "AAAA:{}", addr),
        }
    }
}

impl FromStr for Data {
    type Err = DataParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(DataParseError::MissingType);
        }
        let (rtype, rdata) = (parts[0].to_uppercase(), parts[1]);
        match rtype.as_str() {
            "TXT" => Ok(Data::TXT(rdata.into())),
            "A" => Ok(Data::A(rdata.parse().map_err(DataParseError::Addr)?)),
            "AAAA" => Ok(Data::AAAA(rdata.parse().map_err(DataParseError::Addr)?)),
            _ => Err(DataParseError::UnknownType),
        }
    }
}

#[derive(Debug)]
pub enum DataParseError {
    MissingType,
    UnknownType,
    Addr(net::AddrParseError),
}

impl fmt::Display for DataParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DataParseError::*;
        match self {
            MissingType => write!(f, "missing type"),
            UnknownType => write!(f, "unknown type"),
            Addr(e) => write!(f, "invalid address: {}", e),
        }
    }
}
