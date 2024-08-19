use std::{
    fmt::{self, Write},
    io,
    str::{self, FromStr},
};

use chrono::DateTime;
use data_encoding::{Encoding, BASE32, BASE64, HEXLOWER};
use futures::stream::{FuturesUnordered, Stream};

use trust_dns_client::rr::{
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
    resolver: impl Resolver + 'static,
    options: Query,
) -> impl Stream<Item = Result<Vec<rr::Record>, ResolveError>> {
    let entry = options.entry;
    options
        .record_types
        .into_iter()
        .map(move |rtype| {
            let resolver = resolver.clone();
            let entry = entry.clone();
            async move {
                let lookup = resolver.lookup(entry.clone(), rtype).await?;
                Ok(lookup.record_iter().cloned().collect::<Vec<_>>())
            }
        })
        .collect::<FuturesUnordered<_>>()
}

struct CharacterString<'a>(&'a [u8]);

impl<'a> fmt::Display for CharacterString<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}\"", CharacterStringContents(self.0))?;
        Ok(())
    }
}

struct DisplayStrContents<'a>(&'a str);

struct CharacterStringContents<'a>(&'a [u8]);

impl<'a> fmt::Display for DisplayStrContents<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self.0;
        let mut last_pos = 0;
        while let Some(pos) =
            s[last_pos..].find(|c: char| c == '"' || c.is_control() || c.is_whitespace())
        {
            f.write_str(&s[last_pos..last_pos + pos])?;
            let c = s[last_pos + pos..].chars().next().unwrap();
            match c {
                '"' => f.write_str("\\\"")?,
                ' ' => f.write_char(' ')?,
                c => {
                    let mut buf = [0_u8; 4];
                    for &octet in c.encode_utf8(&mut buf).as_bytes() {
                        write!(f, "\\{:03}", octet)?;
                    }
                }
            }
            last_pos += pos + c.len_utf8();
        }
        f.write_str(&s[last_pos..])?;
        Ok(())
    }
}

impl<'a> fmt::Display for CharacterStringContents<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match str::from_utf8(self.0) {
            Ok(s) => write!(f, "{}", DisplayStrContents(s))?,
            Err(_) => {
                // The data contains non-UTF8 byte sequences. Write ASCII
                // graphic or SPACE octets as-is, and escape all other
                // octets. As this path is expected to be cold, no effort was
                // spent towards making this efficient.
                for &octet in self.0 {
                    if octet.is_ascii_graphic() || octet == b' ' {
                        if octet == b'"' {
                            f.write_str("\\\"")?;
                        } else {
                            f.write_char(char::from(octet))?;
                        }
                    } else {
                        write!(f, "\\{:03}", octet)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
struct DisplayRData<'a>(&'a rr::RData);

impl<'a> fmt::Display for DisplayRData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use rr::RData::*;
        match self.0 {
            A(addr) => write!(f, "{}", addr)?,
            AAAA(addr) => write!(f, "{}", addr)?,
            ANAME(name) => write!(f, "{}", name)?,
            CAA(caa) => {
                let tag = match caa.tag() {
                    caa::Property::Issue => "issue",
                    caa::Property::IssueWild => "issuewild",
                    caa::Property::Iodef => "iodef",
                    caa::Property::Unknown(name) => name,
                };
                write!(f, "{} {} ", if caa.issuer_critical() { 1 } else { 0 }, tag,)?;
                match caa.value() {
                    caa::Value::Issuer(name, kvs) => {
                        f.write_str("\"")?;
                        if let Some(name) = name {
                            write!(f, "{}", name)?;
                            if !kvs.is_empty() {
                                f.write_str(";")?;
                            }
                        } else {
                            f.write_str(";")?;
                        }
                        for kv in kvs {
                            write!(f, "{}={}", kv.key(), kv.value())?;
                        }
                        f.write_str("\"")?;
                    }
                    caa::Value::Url(url) => write!(f, "\"{}\"", DisplayStrContents(url.as_str()))?,
                    caa::Value::Unknown(bytes) => write!(f, "{}", CharacterString(bytes))?,
                }
            }
            CNAME(name) => write!(f, "{}", name)?,
            DNSSEC(sec) => write!(f, "{}", DisplayDNSSECRData(sec))?,
            MX(mx) => write!(f, "{} {}", mx.preference(), mx.exchange())?,
            NAPTR(naptr) => write!(
                f,
                "{} {} {} {} {} {}",
                naptr.order(),
                naptr.preference(),
                CharacterString(naptr.flags()),
                CharacterString(naptr.services()),
                CharacterString(naptr.regexp()),
                naptr.replacement()
            )?,
            NS(name) => write!(f, "{}", name)?,
            OPENPGPKEY(key) => write!(f, "{}", DisplayEncoded(&BASE64, key.public_key()))?,
            PTR(name) => write!(f, "{}", name)?,
            SOA(soa) => {
                write!(
                    f,
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
            SRV(srv) => write!(
                f,
                "{} {} {} {}",
                srv.priority(),
                srv.weight(),
                srv.port(),
                srv.target()
            )?,
            SSHFP(sshfp) => write!(
                f,
                "{} {} {}",
                u8::from(sshfp.algorithm()),
                u8::from(sshfp.fingerprint_type()),
                DisplayEncoded(&HEXLOWER, sshfp.fingerprint())
            )?,
            TLSA(tlsa) => write!(
                f,
                "{} {} {} {}",
                u8::from(tlsa.cert_usage()),
                u8::from(tlsa.selector()),
                u8::from(tlsa.matching()),
                DisplayEncoded(&HEXLOWER, tlsa.cert_data())
            )?,
            TXT(txt) => {
                for (i, data) in txt.txt_data().iter().enumerate() {
                    let chars = CharacterString(data);
                    if i + 1 < txt.txt_data().len() {
                        write!(f, "{} ", chars)?;
                    } else {
                        write!(f, "{}", chars)?;
                    }
                }
            }
            // TODO: What to do with records that have no specified presentation?
            NULL(_) | OPT(_) | Unknown { .. } | ZERO | HINFO(_) | HTTPS(_) | SVCB(_) => {
                write!(f, "{:?}", self.0)?
            }
        }
        Ok(())
    }
}

struct DisplayEncoded<'a>(&'a Encoding, &'a [u8]);

impl<'a> fmt::Display for DisplayEncoded<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: It's a bit unfortunate that this allocates; maybe use a buffer if
        // the input is smaller than some reasonable limit?
        f.write_str(self.0.encode(self.1).as_str())
    }
}

struct ShowTimestamp(u32);

impl fmt::Display for ShowTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let time =
            DateTime::from_timestamp(i64::from(self.0), 0).expect("u32 seconds is always valid");
        write!(f, "{}", time.format("%Y%m%d%H%S"))
    }
}

#[derive(Debug, Copy, Clone)]
struct DisplayDNSSECRData<'a>(&'a DNSSECRData);

impl<'a> fmt::Display for DisplayDNSSECRData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DNSSECRData::*;
        match self.0 {
            DNSKEY(key) => {
                // The MSB is bit 0, hence the subtraction from 15
                let flag_bit = |b, n| (b as u16) << (15 - n);
                let flags = flag_bit(key.zone_key(), 7)
                    | flag_bit(key.revoke(), 8)
                    | flag_bit(key.secure_entry_point(), 15);
                let algorithm = key.algorithm().as_str();
                let protocol = 3; // Fixed value, see RFC 4043, section 2.1.2
                write!(
                    f,
                    "{} {} {} {}",
                    flags,
                    protocol,
                    algorithm,
                    DisplayEncoded(&BASE64, key.public_key())
                )?;
            }
            DS(ds) => {
                let digest_type: u8 = ds.digest_type().into();
                write!(
                    f,
                    "{} {} {} {}",
                    ds.key_tag(),
                    ds.algorithm().as_str(),
                    digest_type,
                    DisplayEncoded(&HEXLOWER, ds.digest()),
                )?;
            }
            KEY(key) => {
                // RFC 2535, section 7.1
                use rdata::key::KeyTrust::*;
                match key.key_trust() {
                    NotAuth => write!(f, "NOAUTH|")?,
                    NotPrivate => write!(f, "NOCONF|")?,
                    DoNotTrust => write!(f, "NOKEY|")?,
                    AuthOrPrivate => {}
                }
                use rdata::key::KeyUsage::*;
                match key.key_usage() {
                    Host => write!(f, "USER|")?,
                    #[allow(deprecated)]
                    Zone => write!(f, "ZONE|")?,
                    Entity => write!(f, "HOST|")?,
                    // TODO: Actually, this has no specified textual representation,
                    // need use switch to numeric representation.
                    Reserved => write!(f, "RESERVED|")?,
                }
                let scope = key.signatory();
                let signatory_bit = |b, n| (b as u8) << (3 - n);
                #[allow(deprecated)]
                let signatory_bits = signatory_bit(scope.zone, 0)
                    | signatory_bit(scope.strong, 1)
                    | signatory_bit(scope.unique, 2)
                    | signatory_bit(scope.general, 3);
                write!(f, "SIG{}", signatory_bits)?;
            }
            NSEC(nsec) => {
                write!(f, "{}", nsec.next_domain_name())?;
                if !nsec.type_bit_maps().is_empty() {
                    write!(f, " {}", DisplayNSECTypeBitMaps(nsec.type_bit_maps()))?;
                }
            }
            NSEC3(nsec3) => {
                // RFC 5155, Section 3.3
                write!(
                    f,
                    "{} {}",
                    DisplayNSEC3Common::from(nsec3),
                    DisplayEncoded(&BASE32, nsec3.next_hashed_owner_name())
                )?;
                if !nsec3.type_bit_maps().is_empty() {
                    write!(f, " {}", DisplayNSECTypeBitMaps(nsec3.type_bit_maps()))?;
                }
            }
            NSEC3PARAM(nsec3param) => write!(f, "{}", DisplayNSEC3Common::from(nsec3param))?,
            SIG(sig) => {
                // RFC 2535, section 7.2
                write!(
                    f,
                    "{} {} {} {} {} {} {} {} {}",
                    sig.type_covered(),
                    sig.algorithm().as_str(),
                    sig.num_labels(),
                    sig.original_ttl(),
                    ShowTimestamp(sig.sig_expiration()),
                    ShowTimestamp(sig.sig_inception()),
                    sig.key_tag(),
                    sig.signer_name(),
                    DisplayEncoded(&BASE64, sig.sig()),
                )?;
            }
            Unknown { rdata, .. } => {
                // This is dubiuos, and I'm not sure how we can even end up here.
                if let Some(data) = rdata.anything() {
                    write!(f, "{}", DisplayEncoded(&BASE64, data))?;
                }
            }
        }
        Ok(())
    }
}

struct DisplayNSEC3Common<'a> {
    hash_algorithm: Nsec3HashAlgorithm,
    opt_out: bool,
    iterations: u16,
    salt: &'a [u8],
}

impl<'a> From<&'a rdata::NSEC3> for DisplayNSEC3Common<'a> {
    fn from(nsec3: &'a rdata::NSEC3) -> Self {
        DisplayNSEC3Common {
            hash_algorithm: nsec3.hash_algorithm(),
            opt_out: nsec3.opt_out(),
            iterations: nsec3.iterations(),
            salt: nsec3.salt(),
        }
    }
}

impl<'a> From<&'a rdata::NSEC3PARAM> for DisplayNSEC3Common<'a> {
    fn from(nsec3: &'a rdata::NSEC3PARAM) -> Self {
        DisplayNSEC3Common {
            hash_algorithm: nsec3.hash_algorithm(),
            opt_out: nsec3.opt_out(),
            iterations: nsec3.iterations(),
            salt: nsec3.salt(),
        }
    }
}

impl<'a> fmt::Display for DisplayNSEC3Common<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // RFC 5155, Section 4.3
        let algo_num: u8 = match self.hash_algorithm {
            Nsec3HashAlgorithm::SHA1 => 1,
        };
        let flags: u8 = self.opt_out as u8;
        write!(f, "{} {} {} ", algo_num, flags, self.iterations)?;
        if self.salt.is_empty() {
            write!(f, "-")?;
        } else {
            write!(f, "{}", DisplayEncoded(&HEXLOWER, self.salt))?;
        }
        Ok(())
    }
}

struct DisplayNSECTypeBitMaps<'a>(&'a [rr::RecordType]);

impl<'a> fmt::Display for DisplayNSECTypeBitMaps<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, record_type) in self.0.iter().enumerate() {
            let sep = if i + 1 == self.0.len() { "" } else { " " };
            write!(f, "{}{}", record_type, sep)?;
        }
        Ok(())
    }
}

pub fn write_record<W: io::Write>(
    writer: &mut W,
    record: &rr::Record,
    format: DisplayFormat,
) -> io::Result<()> {
    match format {
        DisplayFormat::Short => {
            write!(writer, "{}", DisplayRData(record.rdata()))?;
        }
        DisplayFormat::Zone => {
            write!(
                writer,
                "{} {} {} {} {}",
                record.name(),
                record.ttl(),
                record.dns_class(),
                record.record_type(),
                DisplayRData(record.rdata()),
            )?;
        }
    }
    Ok(())
}
