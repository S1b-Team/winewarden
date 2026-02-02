//! DNS packet parser for capturing domain name resolution.
//!
//! This module provides lightweight DNS packet parsing to extract
//! queries and responses from intercepted network traffic.

use std::fmt;

/// Represents a parsed DNS packet
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket {
    /// DNS packet header
    pub header: DnsHeader,
    /// List of questions (queries)
    pub questions: Vec<DnsQuestion>,
    /// List of answer records
    pub answers: Vec<DnsRecord>,
    /// List of authority records
    pub authorities: Vec<DnsRecord>,
    /// List of additional records
    pub additional: Vec<DnsRecord>,
}

/// DNS packet header (12 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    /// Transaction ID
    pub id: u16,
    /// Flags (including QR, opcode, AA, TC, RD, RA, Z, RCODE)
    pub flags: u16,
    /// Number of questions
    pub qdcount: u16,
    /// Number of answer records
    pub ancount: u16,
    /// Number of authority records
    pub nscount: u16,
    /// Number of additional records
    pub arcount: u16,
}

impl DnsHeader {
    /// Returns true if this is a response packet
    pub fn is_response(&self) -> bool {
        (self.flags >> 15) & 1 == 1
    }

    /// Returns true if this is a query packet
    pub fn is_query(&self) -> bool {
        !self.is_response()
    }

    /// Returns the response code (0 = NoError, 3 = NXDomain, etc.)
    pub fn rcode(&self) -> u8 {
        (self.flags & 0x0F) as u8
    }

    /// Returns true if response code indicates success
    pub fn is_success(&self) -> bool {
        self.rcode() == 0
    }
}

/// DNS question (query)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    /// Domain name being queried
    pub name: String,
    /// Query type (A=1, AAAA=28, etc.)
    pub qtype: u16,
    /// Query class (IN=1)
    pub qclass: u16,
}

impl DnsQuestion {
    /// Returns true if this is an A record query (IPv4)
    pub fn is_a(&self) -> bool {
        self.qtype == 1
    }

    /// Returns true if this is an AAAA record query (IPv6)
    pub fn is_aaaa(&self) -> bool {
        self.qtype == 28
    }
}

/// DNS resource record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Domain name
    pub name: String,
    /// Record type
    pub rtype: u16,
    /// Record class
    pub rclass: u16,
    /// Time to live
    pub ttl: u32,
    /// Record data
    pub rdata: RecordData,
}

/// DNS record data types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// IPv4 address (A record)
    A([u8; 4]),
    /// IPv6 address (AAAA record)
    AAAA([u8; 16]),
    /// Canonical name (CNAME record)
    CNAME(String),
    /// Name server (NS record)
    NS(String),
    /// Mail exchange (MX record)
    MX { preference: u16, exchange: String },
    /// Text record
    TXT(String),
    /// Service record
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Raw data for unknown types
    Raw(Vec<u8>),
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordData::A(ip) => write!(f, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]),
            RecordData::AAAA(ip) => {
                // Format IPv6 address
                let segments: Vec<String> = ip
                    .chunks(2)
                    .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk[1]))
                    .collect();
                write!(f, "{}", segments.join(":"))
            }
            RecordData::CNAME(name) | RecordData::NS(name) => write!(f, "{}", name),
            RecordData::MX {
                preference,
                exchange,
            } => {
                write!(f, "{} {}", preference, exchange)
            }
            RecordData::TXT(text) => write!(f, "\"{}\"", text),
            RecordData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                write!(f, "{} {} {} {}", priority, weight, port, target)
            }
            RecordData::Raw(data) => write!(f, "[{} bytes]", data.len()),
        }
    }
}

/// Errors that can occur during DNS packet parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Packet too short to contain valid DNS header
    TooShort,
    /// Invalid domain name encoding
    InvalidName,
    /// Truncated packet
    Truncated,
    /// Unsupported or invalid record type
    InvalidRecordType(u16),
    /// Invalid pointer in name compression
    InvalidPointer,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TooShort => write!(f, "DNS packet too short"),
            ParseError::InvalidName => write!(f, "Invalid domain name encoding"),
            ParseError::Truncated => write!(f, "Truncated DNS packet"),
            ParseError::InvalidRecordType(t) => write!(f, "Invalid record type: {}", t),
            ParseError::InvalidPointer => write!(f, "Invalid name compression pointer"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses a DNS packet from raw bytes
pub fn parse_packet(data: &[u8]) -> Result<DnsPacket, ParseError> {
    if data.len() < 12 {
        return Err(ParseError::TooShort);
    }

    let header = parse_header(data)?;
    let mut offset = 12;

    // Parse questions
    let mut questions = Vec::new();
    for _ in 0..header.qdcount {
        let (name, qtype, qclass, new_offset) = parse_question(data, offset)?;
        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
        offset = new_offset;
    }

    // Parse answers
    let mut answers = Vec::new();
    for _ in 0..header.ancount {
        let (record, new_offset) = parse_record(data, offset)?;
        answers.push(record);
        offset = new_offset;
    }

    // Parse authorities
    let mut authorities = Vec::new();
    for _ in 0..header.nscount {
        let (record, new_offset) = parse_record(data, offset)?;
        authorities.push(record);
        offset = new_offset;
    }

    // Parse additional
    let mut additional = Vec::new();
    for _ in 0..header.arcount {
        let (record, new_offset) = parse_record(data, offset)?;
        additional.push(record);
        offset = new_offset;
    }

    Ok(DnsPacket {
        header,
        questions,
        answers,
        authorities,
        additional,
    })
}

/// Parses the DNS header (first 12 bytes)
fn parse_header(data: &[u8]) -> Result<DnsHeader, ParseError> {
    Ok(DnsHeader {
        id: u16::from_be_bytes([data[0], data[1]]),
        flags: u16::from_be_bytes([data[2], data[3]]),
        qdcount: u16::from_be_bytes([data[4], data[5]]),
        ancount: u16::from_be_bytes([data[6], data[7]]),
        nscount: u16::from_be_bytes([data[8], data[9]]),
        arcount: u16::from_be_bytes([data[10], data[11]]),
    })
}

/// Parses a DNS question section
fn parse_question(data: &[u8], offset: usize) -> Result<(String, u16, u16, usize), ParseError> {
    let (name, mut pos) = parse_name(data, offset)?;

    if pos + 4 > data.len() {
        return Err(ParseError::Truncated);
    }

    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    let qclass = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    Ok((name, qtype, qclass, pos))
}

/// Parses a DNS resource record
fn parse_record(data: &[u8], offset: usize) -> Result<(DnsRecord, usize), ParseError> {
    let (name, mut pos) = parse_name(data, offset)?;

    if pos + 10 > data.len() {
        return Err(ParseError::Truncated);
    }

    let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    let rclass = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    let ttl = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    pos += 4;
    let rdlength = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    if pos + rdlength > data.len() {
        return Err(ParseError::Truncated);
    }

    let rdata = parse_rdata(data, pos, rtype, rdlength)?;
    pos += rdlength;

    Ok((
        DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        },
        pos,
    ))
}

/// Parses a domain name (handling compression)
fn parse_name(data: &[u8], offset: usize) -> Result<(String, usize), ParseError> {
    let mut name_parts = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut jump_offset = offset;

    loop {
        if pos >= data.len() {
            return Err(ParseError::Truncated);
        }

        let label_len = data[pos];

        // Check for compression pointer (11xxxxxx)
        if label_len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return Err(ParseError::Truncated);
            }
            let pointer = u16::from_be_bytes([data[pos] & 0x3F, data[pos + 1]]) as usize;
            if pointer >= data.len() {
                return Err(ParseError::InvalidPointer);
            }
            if !jumped {
                jump_offset = pos + 2;
            }
            pos = pointer;
            jumped = true;
            continue;
        }

        // End of name (null label)
        if label_len == 0 {
            pos += 1;
            break;
        }

        // Regular label
        pos += 1;
        if pos + label_len as usize > data.len() {
            return Err(ParseError::Truncated);
        }
        let label = String::from_utf8_lossy(&data[pos..pos + label_len as usize]);
        name_parts.push(label.to_string());
        pos += label_len as usize;
    }

    let final_offset = if jumped { jump_offset } else { pos };
    Ok((name_parts.join("."), final_offset))
}

/// Parses record data based on record type
fn parse_rdata(
    data: &[u8],
    offset: usize,
    rtype: u16,
    rdlength: usize,
) -> Result<RecordData, ParseError> {
    match rtype {
        1 => {
            // A record (IPv4)
            if rdlength != 4 {
                return Err(ParseError::Truncated);
            }
            Ok(RecordData::A([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]))
        }
        5 => {
            // CNAME record
            let (name, _) = parse_name(data, offset)?;
            Ok(RecordData::CNAME(name))
        }
        15 => {
            // MX record
            if rdlength < 3 {
                return Err(ParseError::Truncated);
            }
            let preference = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let (exchange, _) = parse_name(data, offset + 2)?;
            Ok(RecordData::MX {
                preference,
                exchange,
            })
        }
        16 => {
            // TXT record
            let txt_len = data[offset] as usize;
            if offset + 1 + txt_len > data[offset..].len() + offset {
                return Err(ParseError::Truncated);
            }
            let text = String::from_utf8_lossy(&data[offset + 1..offset + 1 + txt_len]);
            Ok(RecordData::TXT(text.to_string()))
        }
        28 => {
            // AAAA record (IPv6)
            if rdlength != 16 {
                return Err(ParseError::Truncated);
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&data[offset..offset + 16]);
            Ok(RecordData::AAAA(addr))
        }
        2 => {
            // NS record
            let (name, _) = parse_name(data, offset)?;
            Ok(RecordData::NS(name))
        }
        33 => {
            // SRV record
            if rdlength < 7 {
                return Err(ParseError::Truncated);
            }
            let priority = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let weight = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let port = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            let (target, _) = parse_name(data, offset + 6)?;
            Ok(RecordData::SRV {
                priority,
                weight,
                port,
                target,
            })
        }
        _ => {
            // Unknown type - store raw data
            Ok(RecordData::Raw(data[offset..offset + rdlength].to_vec()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // DNS query packet for "example.com" A record
    const DNS_QUERY: &[u8] = &[
        0x00, 0x01, // Transaction ID
        0x01, 0x00, // Flags: Standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // Question: example.com
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
        0x01, // Query type: A
        0x00, 0x01, // Query class: IN
    ];

    #[test]
    fn test_parse_header() {
        let header = parse_header(DNS_QUERY).unwrap();
        assert_eq!(header.id, 1);
        assert!(header.is_query());
        assert!(!header.is_response());
        assert_eq!(header.qdcount, 1);
        assert_eq!(header.ancount, 0);
    }

    #[test]
    fn test_parse_name() {
        let name = parse_name(DNS_QUERY, 12);
        assert!(name.is_ok());
        let (domain, offset) = name.unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(offset, 25); // 12 + 7 + 1 + 3 + 1 + 1 (for type)
    }

    #[test]
    fn test_parse_packet() {
        let packet = parse_packet(DNS_QUERY).unwrap();
        assert_eq!(packet.header.id, 1);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "example.com");
        assert_eq!(packet.questions[0].qtype, 1); // A record
    }

    #[test]
    fn test_parse_empty() {
        let result = parse_packet(&[]);
        assert!(matches!(result, Err(ParseError::TooShort)));
    }
}
