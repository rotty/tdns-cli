use std::{fmt, io, str::FromStr};

use futures::stream::{FuturesUnordered, Stream};
use futures_util::FutureExt;

use trust_dns::rr;
use trust_dns_resolver::error::ResolveError;

use crate::Resolver;

#[derive(Debug, Clone)]
pub enum ParseDisplayFormatError {
    UnknownFormat,
}

impl fmt::Display for ParseDisplayFormatError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseDisplayFormatError::*;
        match self {
            UnknownFormat => write!(f, "unknown format"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum DisplayFormat {
    Short,
    Zone,
}

impl FromStr for DisplayFormat {
    type Err = ParseDisplayFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "short" => Ok(DisplayFormat::Short),
            "zone" => Ok(DisplayFormat::Zone),
            _ => Err(ParseDisplayFormatError::UnknownFormat),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Query {
    pub entry: rr::Name,
    pub record_types: Vec<rr::RecordType>,
    pub display_format: DisplayFormat,
}

pub fn perform_query(
    resolver: impl Resolver,
    options: Query,
) -> impl Stream<Item = Result<Vec<rr::Record>, ResolveError>> {
    let entry = options.entry;
    options
        .record_types
        .into_iter()
        .map(|rtype| {
            resolver.lookup(entry.clone(), rtype).map(|result| {
                result.map(|lookup| lookup.record_iter().cloned().collect::<Vec<_>>())
            })
        })
        .collect::<FuturesUnordered<_>>()
}

fn write_rdata<W: io::Write>(writer: &mut W, rdata: &rr::RData) -> io::Result<()> {
    use rr::RData::*;
    match rdata {
        A(addr) => write!(writer, "{}", addr)?,
        AAAA(addr) => write!(writer, "{}", addr)?,
        TXT(txt) => {
            for (i, data) in txt.txt_data().iter().enumerate() {
                // TODO: proper (lossless) display of TXT data
                let content = String::from_utf8_lossy(data);
                if i + 1 < txt.txt_data().len() {
                    write!(writer, r#""{}" "#, content)?;
                } else {
                    write!(writer, r#""{}""#, content)?;
                }
            }
        }
        NS(name) => {
            write!(writer, "{}", name)?;
        }
        MX(mx) => {
            write!(writer, "{} {}", mx.preference(), mx.exchange())?;
        }
        SOA(soa) => {
            write!(
                writer,
                "{} {} {} {} {} {} {}",
                soa.mname(),
                soa.rname(),
                soa.serial(),
                soa.refresh(),
                soa.retry(),
                soa.expire(),
                soa.minimum()
            )?;
        }
        // TODO: display other records properly
        other => write!(writer, "{:?}", other)?,
    }
    Ok(())
}

pub fn write_record<W: io::Write>(
    writer: &mut W,
    record: &rr::Record,
    format: DisplayFormat,
) -> io::Result<()> {
    match format {
        DisplayFormat::Short => {
            write_rdata(writer, record.rdata())?;
        }
        DisplayFormat::Zone => {
            write!(
                writer,
                "{} {} {} {} ",
                record.name(),
                record.ttl(),
                record.dns_class(),
                record.record_type(),
            )?;
            write_rdata(writer, record.rdata())?;
        }
    }
    Ok(())
}
