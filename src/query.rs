use std::{fmt, io, str::FromStr};

use chrono::NaiveDateTime;
use data_encoding::{Encoding, BASE32, BASE64, HEXLOWER};
use futures::stream::{FuturesUnordered, Stream};
use futures_util::FutureExt;

use trust_dns::rr::{
    self,
    dnssec::Nsec3HashAlgorithm,
    rdata::{self, caa, DNSSECRData},
};
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
        CAA(caa) => {
            let tag = match caa.tag() {
                caa::Property::Issue => "issue",
                caa::Property::IssueWild => "issuewild",
                caa::Property::Iodef => "iodef",
                caa::Property::Unknown(name) => name,
            };
            write!(
                writer,
                "{} {} ",
                if caa.issuer_critical() { 1 } else { 0 },
                tag,
            )?;
            match caa.value() {
                caa::Value::Issuer(name, kvs) => {
                    writer.write_all(b"\"")?;
                    if let Some(name) = name {
                        // TODO: quoting?
                        write!(writer, "{}", name)?;
                        if !kvs.is_empty() {
                            writer.write_all(b";")?;
                        }
                    } else {
                        writer.write_all(b";")?;
                    }
                    for kv in kvs {
                        write!(writer, "{}={}", kv.key(), kv.value())?;
                    }
                    writer.write_all(b"\"")?;
                }
                // TODO: quoting?
                caa::Value::Url(url) => write!(writer, "\"{}\"", url)?,
                caa::Value::Unknown(bytes) => {
                    // TODO: proper (lossless) display of data
                    let s = String::from_utf8_lossy(bytes);
                    write!(writer, "\"{}\"", s)?;
                }
            };
        }
        DNSSEC(sec) => write_dnssec_rdata(writer, sec)?,
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

fn write_encoded<W: io::Write>(writer: &mut W, encoding: &Encoding, data: &[u8]) -> io::Result<()> {
    // TODO: It's a bit unfortunate that this allocates; maybe use a buffer if
    // the input is smaller than some reasonable limit?
    writer.write_all(encoding.encode(data).as_bytes())?;
    Ok(())
}

struct ShowTimestamp(u32);

impl fmt::Display for ShowTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let time = NaiveDateTime::from_timestamp(i64::from(self.0), 0);
        write!(f, "{}", time.format("%Y%m%d%H%S"))
    }
}

fn write_dnssec_rdata<W: io::Write>(writer: &mut W, data: &DNSSECRData) -> io::Result<()> {
    use DNSSECRData::*;
    match data {
        DNSKEY(key) => {
            // The MSB is bit 0, hence the subtraction from 15
            let flag_bit = |b, n| (b as u16) << (15 - n);
            let flags = flag_bit(key.zone_key(), 7)
                | flag_bit(key.revoke(), 8)
                | flag_bit(key.secure_entry_point(), 15);
            let algorithm = key.algorithm().as_str();
            let protocol = 3; // Fixed value, see RFC 4043, section 2.1.2
            write!(writer, "{} {} {} ", flags, protocol, algorithm)?;
            write_encoded(writer, &BASE64, key.public_key())?;
        }
        DS(ds) => {
            let digest_type: u8 = ds.digest_type().into();
            write!(
                writer,
                "{} {} {} ",
                ds.key_tag(),
                ds.algorithm().as_str(),
                digest_type
            )?;
            write_encoded(writer, &HEXLOWER, ds.digest())?;
        }
        KEY(key) => {
            // RFC 2535, section 7.1
            use rdata::key::KeyTrust::*;
            match key.key_trust() {
                NotAuth => write!(writer, "NOAUTH|")?,
                NotPrivate => write!(writer, "NOCONF|")?,
                DoNotTrust => write!(writer, "NOKEY|")?,
                AuthOrPrivate => {}
            }
            use rdata::key::KeyUsage::*;
            match key.key_usage() {
                Host => write!(writer, "USER|")?,
                #[allow(deprecated)]
                Zone => write!(writer, "ZONE|")?,
                Entity => write!(writer, "HOST|")?,
                // TODO: Actually, this has no specified textual representation,
                // need use switch to numeric representation.
                Reserved => write!(writer, "RESERVED|")?,
            }
            let scope = key.signatory();
            let signatory_bit = |b, n| (b as u8) << (3 - n);
            #[allow(deprecated)]
            let signatory_bits = signatory_bit(scope.zone, 0)
                | signatory_bit(scope.strong, 1)
                | signatory_bit(scope.unique, 2)
                | signatory_bit(scope.general, 3);
            write!(writer, "SIG{}", signatory_bits)?;
        }
        NSEC(nsec) => {
            write!(writer, "{}", nsec.next_domain_name())?;
            if !nsec.type_bit_maps().is_empty() {
                write!(writer, " ")?;
                write_nsec_type_bit_maps(writer, nsec.type_bit_maps())?;
            }
        }
        NSEC3(nsec3) => {
            // RFC 5155, Section 3.3
            write_nsec3_common(
                writer,
                nsec3.hash_algorithm(),
                nsec3.opt_out(),
                nsec3.iterations(),
                nsec3.salt(),
            )?;
            write!(writer, " ")?;
            write_encoded(writer, &BASE32, nsec3.next_hashed_owner_name())?;
            if !nsec3.type_bit_maps().is_empty() {
                write!(writer, " ")?;
                write_nsec_type_bit_maps(writer, nsec3.type_bit_maps())?;
            }
        }
        NSEC3PARAM(nsec3) => {
            write_nsec3_common(
                writer,
                nsec3.hash_algorithm(),
                nsec3.opt_out(),
                nsec3.iterations(),
                nsec3.salt(),
            )?;
        }
        SIG(sig) => {
            // RFC 2535, section 7.2
            write!(
                writer,
                "{} {} {} {} {} {} {} {} ",
                sig.type_covered(),
                sig.algorithm().as_str(),
                sig.num_labels(),
                sig.original_ttl(),
                ShowTimestamp(sig.sig_expiration()),
                ShowTimestamp(sig.sig_inception()),
                sig.key_tag(),
                sig.signer_name(),
            )?;
            write_encoded(writer, &BASE64, sig.sig())?;
        }
        Unknown { rdata, .. } => {
            // This is dubiuos' I'm not sure how we can even end up here.
            if let Some(data) = rdata.anything() {
                write_encoded(writer, &BASE64, data)?;
            }
        }
    }
    Ok(())
}

fn write_nsec3_common<W: io::Write>(
    writer: &mut W,
    hash_algorithm: Nsec3HashAlgorithm,
    opt_out: bool,
    iterations: u16,
    salt: &[u8],
) -> io::Result<()> {
    // RFC 5155, Section 4.3
    let algo_num: u8 = match hash_algorithm {
        Nsec3HashAlgorithm::SHA1 => 1,
    };
    let flags: u8 = opt_out as u8;
    write!(writer, "{} {} {} ", algo_num, flags, iterations)?;
    if salt.len() == 0 {
        write!(writer, "-")?;
    } else {
        write_encoded(writer, &HEXLOWER, salt)?;
    }
    Ok(())
}

fn write_nsec_type_bit_maps<W: io::Write>(
    writer: &mut W,
    record_types: &[rr::RecordType],
) -> io::Result<()> {
    for (i, record_type) in record_types.iter().enumerate() {
        let sep = if i + 1 == record_types.len() { "" } else { " " };
        write!(writer, "{}{}", record_type, sep)?;
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
