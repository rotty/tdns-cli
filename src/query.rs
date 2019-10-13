use std::{
    io::{self, Write},
    str::FromStr,
    fmt,
};

use futures::{future, Future};

use trust_dns::{
    client::ClientHandle,
    proto::xfer::{DnsHandle, DnsResponse},
    rr,
};

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
    mut resolver: impl DnsHandle,
    options: Query,
) -> impl Future<Item = Vec<DnsResponse>, Error = failure::Error> {
    let entry = options.entry;
    future::join_all(options.record_types.into_iter().map(move |rtype| {
        resolver
            .query(entry.clone(), rr::DNSClass::IN, rtype)
            .map_err(Into::into)
    }))
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

fn write_record<W: io::Write>(
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
                "{} {} {} ",
                record.name(),
                record.ttl(),
                record.dns_class()
            )?;
            write_rdata(writer, record.rdata())?;
        }
    }
    Ok(())
}

pub fn print_dns_response(responses: &[DnsResponse], options: &Query) -> io::Result<()> {
    let mut stdout = io::stdout();
    for response in responses {
        for answer in response.answers() {
            write_record(&mut stdout, answer, options.display_format)?;
            stdout.write_all(b"\n")?;
        }
    }
    Ok(())
}
