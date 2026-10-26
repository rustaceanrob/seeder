use std::{
    io::{Cursor, Seek},
    net::IpAddr,
};

const MAX_NAME_LEN: usize = 255;
// The question always begins directly after the 12 byte header.
const QUESTION_NAME_OFFSET: u16 = 12;

pub struct Configuration<'a> {
    // e.g. seed.example.com
    pub hostname: &'a str,
    // The nameserver name e.g. ns1.example.com
    pub nameserver: &'a str,
    // Email for the admin admin.example.com
    pub hostmaster: &'a str,
    // Time until cached response must be requested again
    pub ttl: u32,
    // Number of records to respond with
    pub query_answers: usize,
}

#[derive(Debug, Clone, Copy)]
struct Id(u16);

impl Id {
    fn new(id: u16) -> Self {
        Self(id)
    }

    fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QType(u16);

impl QType {
    const A: Self = Self(1);
    const NS: Self = Self(2);
    const SOA: Self = Self(6);
    const AAAA: Self = Self(28);
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QClass(u16);

impl QClass {
    const IN: Self = Self(1);
}

struct RecursionBit(u8);

impl RecursionBit {
    fn new(raw: u8) -> Self {
        RecursionBit(raw & 0x01)
    }

    fn flag(self) -> u16 {
        (self.0 as u16) << 8
    }
}

struct ResponseCode(u16);

impl ResponseCode {
    const NO_ERROR: Self = Self(0);
    const NO_DOMAIN: Self = Self(3);
    const REFUSED: Self = Self(5);
}

#[derive(Debug, Clone, Copy)]
struct Flags(u16);

impl Flags {
    fn new(recursion: RecursionBit, response_code: ResponseCode) -> Self {
        // QR = response | AA | echo recursion bit | response code
        Self(0x8000 | 0x0400 | recursion.flag() | response_code.0)
    }

    fn refused(recursion: RecursionBit) -> Self {
        // Not authoritative for names outside the zone, so AA is left unset.
        Self(0x8000 | recursion.flag() | ResponseCode::REFUSED.0)
    }

    fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

fn encode_uncompressed_name_to_vec(name: &str, buf: &mut Vec<u8>) {
    for label in name.split(".") {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    // Termination byte.
    buf.push(0x00);
}

/// Length of `name` as written by `encode_uncompressed_name_to_vec`.
fn encoded_name_len(name: &str) -> usize {
    name.split(".").map(|label| label.len() + 1).sum::<usize>() + 1
}

/// Decode a possibly compressed domain name (RFC 1035 4.1.4).
///
/// Compression pointers are offsets from the start of the message, so the reader must be
/// positioned relative to the full message. On return, the reader sits just past the name
/// as it appears in the stream, regardless of any pointers followed.
fn decode_name<R: std::io::Read + std::io::Seek>(reader: &mut R) -> std::io::Result<String> {
    let mut name = String::new();
    // Wire length: each label plus its length byte, plus the root byte.
    let mut wire_len = 1;
    // Where to resume after following the first pointer.
    let mut resume_at = None;
    // Every pointer must jump strictly before the last, which rules out loops.
    let mut floor = reader.stream_position()?;
    loop {
        let byte = read_u8(reader)?;
        match byte >> 6 {
            0b00 if byte == 0 => break,
            0b00 => {
                wire_len += byte as usize + 1;
                if wire_len > MAX_NAME_LEN {
                    return Err(invalid_data("Name exceeds 255 bytes."));
                }
                let mut label = vec![0u8; byte as usize];
                reader.read_exact(&mut label)?;
                let label =
                    std::str::from_utf8(&label).map_err(|_| invalid_data("Label is not UTF-8."))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(label);
            }
            0b11 => {
                let offset = u16::from_be_bytes([byte & 0x3F, read_u8(reader)?]) as u64;
                if offset >= floor {
                    return Err(invalid_data("Compression pointer does not point backward."));
                }
                floor = offset;
                if resume_at.is_none() {
                    resume_at = Some(reader.stream_position()?);
                }
                reader.seek(std::io::SeekFrom::Start(offset))?;
            }
            _ => return Err(invalid_data("Reserved label type.")),
        }
    }
    if let Some(pos) = resume_at {
        reader.seek(std::io::SeekFrom::Start(pos))?;
    }
    Ok(name)
}

#[derive(Debug)]
struct AnswerSection {
    id: Id,
    flags: Flags,
    answers: u16,
    answer_buf: Vec<u8>,
}

impl AnswerSection {
    fn empty(id: Id, flags: Flags, question: &[u8]) -> Vec<u8> {
        let mut out_buf = Vec::with_capacity(512);
        out_buf.extend_from_slice(&id.to_be_bytes());
        out_buf.extend_from_slice(&flags.to_be_bytes());
        out_buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out_buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out_buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out_buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        out_buf.extend_from_slice(question);
        out_buf
    }

    fn soa_response(id: Id, flags: Flags, config: &Configuration<'_>) -> Self {
        let timers = [1u32, 3600, 600, 86400, config.ttl];
        let rdlength = encoded_name_len(config.nameserver)
            + encoded_name_len(config.hostmaster)
            + timers.len() * 4;
        let mut answer_buf = Vec::new();
        write_record_header(&mut answer_buf, &QType::SOA, config.ttl, rdlength as u16);
        encode_uncompressed_name_to_vec(config.nameserver, &mut answer_buf);
        encode_uncompressed_name_to_vec(config.hostmaster, &mut answer_buf);
        for data in timers {
            write_u32_be(&mut answer_buf, data);
        }
        Self {
            id,
            flags,
            answers: 1,
            answer_buf,
        }
    }

    fn ns_response(id: Id, flags: Flags, config: &Configuration<'_>) -> AnswerSection {
        let rdlength = encoded_name_len(config.nameserver);
        let mut answer_buf = Vec::new();
        write_record_header(&mut answer_buf, &QType::NS, config.ttl, rdlength as u16);
        encode_uncompressed_name_to_vec(config.nameserver, &mut answer_buf);
        Self {
            id,
            flags,
            answers: 1,
            answer_buf,
        }
    }

    fn a_or_aaaa_response<'a>(
        id: Id,
        flags: Flags,
        config: &Configuration<'a>,
        ips: impl Iterator<Item = &'a IpAddr>,
        qtype: QType,
    ) -> AnswerSection {
        let mut data = Vec::new();
        let mut matched = 0u16;
        for ip in ips.take(config.query_answers) {
            match ip {
                IpAddr::V4(ipv4) => {
                    write_record_header(&mut data, &qtype, config.ttl, 4);
                    data.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    write_record_header(&mut data, &qtype, config.ttl, 16);
                    data.extend_from_slice(&ipv6.octets());
                }
            }
            matched += 1;
        }
        Self {
            id,
            flags,
            answers: matched,
            answer_buf: data,
        }
    }

    fn finish(self, question: &[u8]) -> Vec<u8> {
        let mut out_buf = Vec::new();
        out_buf.extend_from_slice(&self.id.to_be_bytes());
        out_buf.extend_from_slice(&self.flags.to_be_bytes());
        out_buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out_buf.extend_from_slice(&self.answers.to_be_bytes()); // ANCOUNT
        out_buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out_buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        out_buf.extend_from_slice(question);
        out_buf.extend_from_slice(&self.answer_buf);
        out_buf
    }
}

pub fn build_reponse(
    data: &[u8],
    config: Configuration<'_>,
    sample: &[IpAddr],
) -> std::io::Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(invalid_data("Data length is too short."));
    }
    let mut reader = Cursor::new(data);
    let id = Id::new(read_u16_be(&mut reader)?);
    let flags_high = read_u8(&mut reader)?;
    if flags_high & 0x80 != 0 {
        return Err(invalid_data("Message is a response, not a query."));
    }
    let recurse_bit = RecursionBit::new(flags_high);
    let _flags_low = read_u8(&mut reader)?;
    let qcount = read_u16_be(&mut reader)?;
    if qcount == 0 {
        return Err(invalid_data("QCount must be nonzero."));
    }
    let _ancount = read_u16_be(&mut reader)?;
    let _nscount = read_u16_be(&mut reader)?;
    let _arcount = read_u16_be(&mut reader)?;
    let question_start = reader.stream_position()? as usize;
    let name = decode_name(&mut reader)?;
    let qtype = QType(read_u16_be(&mut reader)?);
    let qclass = QClass(read_u16_be(&mut reader)?);
    let question_end = reader.stream_position()? as usize;
    let question = &data[question_start..question_end];
    if qclass != QClass::IN {
        return Err(invalid_data("Invalid QClass"));
    }
    if is_subdomain(&name, config.hostname) {
        let err = ResponseCode::NO_DOMAIN;
        let flags = Flags::new(recurse_bit, err);
        return Ok(AnswerSection::empty(id, flags, question));
    }
    if !name.eq_ignore_ascii_case(config.hostname) {
        let flags = Flags::refused(recurse_bit);
        return Ok(AnswerSection::empty(id, flags, question));
    }
    if qtype == QType::A {
        let ip_iter = sample.iter().filter(|f| f.is_ipv4());
        let rsp = ResponseCode::NO_ERROR;
        let flags = Flags::new(recurse_bit, rsp);
        return Ok(
            AnswerSection::a_or_aaaa_response(id, flags, &config, ip_iter, QType::A)
                .finish(question),
        );
    }
    if qtype == QType::AAAA {
        let ip_iter = sample.iter().filter(|f| f.is_ipv6());
        let rsp = ResponseCode::NO_ERROR;
        let flags = Flags::new(recurse_bit, rsp);
        return Ok(
            AnswerSection::a_or_aaaa_response(id, flags, &config, ip_iter, QType::AAAA)
                .finish(question),
        );
    }
    if qtype == QType::SOA {
        let rsp = ResponseCode::NO_ERROR;
        let flags = Flags::new(recurse_bit, rsp);
        return Ok(AnswerSection::soa_response(id, flags, &config).finish(question));
    }
    if qtype == QType::NS {
        let rsp = ResponseCode::NO_ERROR;
        let flags = Flags::new(recurse_bit, rsp);
        return Ok(AnswerSection::ns_response(id, flags, &config).finish(question));
    }
    // The name exists but has no records of this type (NODATA).
    let rsp = ResponseCode::NO_ERROR;
    let flags = Flags::new(recurse_bit, rsp);
    Ok(AnswerSection::empty(id, flags, question))
}

/// Whether `name` sits strictly below `zone`, ignoring ASCII case.
fn is_subdomain(name: &str, zone: &str) -> bool {
    let (name, zone) = (name.as_bytes(), zone.as_bytes());
    name.len() > zone.len() + 1
        && name[name.len() - zone.len() - 1] == b'.'
        && name[name.len() - zone.len()..].eq_ignore_ascii_case(zone)
}

fn invalid_data(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

#[inline]
fn read_u8<R: std::io::Read>(reader: &mut R) -> std::io::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

#[inline]
fn read_u16_be<R: std::io::Read>(reader: &mut R) -> std::io::Result<u16> {
    let mut bytes = [0u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_be_bytes(bytes))
}

fn write_u16_be(writer: &mut Vec<u8>, bytes: u16) {
    writer.extend_from_slice(&bytes.to_be_bytes());
}

fn write_u32_be(writer: &mut Vec<u8>, bytes: u32) {
    writer.extend_from_slice(&bytes.to_be_bytes());
}

/// Write the fixed portion of a resource record (RFC 1035 4.1.3), up to and including RDLENGTH.
///
/// Every answer is for the queried name, so NAME is a compression pointer to the question.
fn write_record_header(writer: &mut Vec<u8>, qtype: &QType, ttl: u32, rdlength: u16) {
    write_u16_be(writer, 0xC000 | QUESTION_NAME_OFFSET);
    write_u16_be(writer, qtype.0);
    write_u16_be(writer, QClass::IN.0);
    write_u32_be(writer, ttl);
    write_u16_be(writer, rdlength);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Seek};

    #[test]
    fn decodes_uncompressed_name() {
        let mut buf = Vec::new();
        encode_uncompressed_name_to_vec("seed.example.com", &mut buf);
        buf.push(0xFF);
        let mut reader = Cursor::new(buf.as_slice());
        assert_eq!(decode_name(&mut reader).unwrap(), "seed.example.com");
        assert_eq!(read_u8(&mut reader).unwrap(), 0xFF);
    }

    #[test]
    fn decodes_compressed_name() {
        let mut buf = Vec::new();
        encode_uncompressed_name_to_vec("example.com", &mut buf);
        let start = buf.len() as u64;
        // "seed" followed by a pointer to "example.com" at offset 0.
        buf.extend_from_slice(&[4, b's', b'e', b'e', b'd', 0xC0, 0x00, 0xFF]);
        let mut reader = Cursor::new(buf.as_slice());
        reader.seek(std::io::SeekFrom::Start(start)).unwrap();
        assert_eq!(decode_name(&mut reader).unwrap(), "seed.example.com");
        assert_eq!(read_u8(&mut reader).unwrap(), 0xFF);
    }

    #[test]
    fn encoded_name_len_matches_encoding() {
        for name in ["seed.example.com", "com", "a.b"] {
            let mut buf = Vec::new();
            encode_uncompressed_name_to_vec(name, &mut buf);
            assert_eq!(encoded_name_len(name), buf.len());
        }
    }

    #[test]
    fn decodes_root_name() {
        let mut reader = Cursor::new([0u8].as_slice());
        assert_eq!(decode_name(&mut reader).unwrap(), "");
    }

    #[test]
    fn rejects_pointer_loop() {
        let mut reader = Cursor::new([0xC0u8, 0x00].as_slice());
        assert!(decode_name(&mut reader).is_err());
    }

    #[test]
    fn rejects_overlong_name() {
        let mut buf = Vec::new();
        for _ in 0..5 {
            buf.push(63);
            buf.extend_from_slice(&[b'a'; 63]);
        }
        buf.push(0);
        assert!(decode_name(&mut Cursor::new(buf.as_slice())).is_err());
    }

    fn test_config() -> Configuration<'static> {
        Configuration {
            hostname: "seed.example.com",
            nameserver: "ns1.example.com",
            hostmaster: "admin.example.com",
            ttl: 60,
            query_answers: 1,
        }
    }

    fn query(flags_high: u8, name: &str, qtype: QType) -> Vec<u8> {
        let mut query = vec![0xAB, 0xCD, flags_high, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        encode_uncompressed_name_to_vec(name, &mut query);
        write_u16_be(&mut query, qtype.0);
        write_u16_be(&mut query, QClass::IN.0);
        query
    }

    fn rcode_and_aa(response: &[u8]) -> (u8, bool) {
        (response[3] & 0x0F, response[2] & 0x04 != 0)
    }

    #[test]
    fn drops_responses() {
        let query = query(0x81, "seed.example.com", QType::A);
        assert!(build_reponse(&query, test_config(), &[]).is_err());
    }

    #[test]
    fn answers_nodata_for_unsupported_type() {
        let query = query(0x01, "seed.example.com", QType(65));
        let response = build_reponse(&query, test_config(), &[]).unwrap();
        assert_eq!(rcode_and_aa(&response), (0, true));
        assert_eq!(&response[6..8], &0u16.to_be_bytes()); // ANCOUNT
    }

    #[test]
    fn answers_nxdomain_below_zone() {
        let query = query(0x01, "x.SEED.example.com", QType::A);
        let response = build_reponse(&query, test_config(), &[]).unwrap();
        assert_eq!(rcode_and_aa(&response), (3, true));
    }

    #[test]
    fn refuses_outside_zone() {
        for name in ["example.com", "evilseed.example.com", "seed.example.org"] {
            let query = query(0x01, name, QType::A);
            let response = build_reponse(&query, test_config(), &[]).unwrap();
            assert_eq!(rcode_and_aa(&response), (5, false), "{name}");
            assert_eq!(&response[2..3], &[0x81]); // QR | echoed RD
        }
    }

    #[test]
    fn answers_a_query_with_records() {
        let config = Configuration {
            hostname: "seed.example.com",
            nameserver: "ns1.example.com",
            hostmaster: "admin.example.com",
            ttl: 60,
            query_answers: 1,
        };
        let mut query = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        encode_uncompressed_name_to_vec("seed.example.com", &mut query);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let sample: Vec<IpAddr> = vec![
            "2001:db8::1".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
        ];
        let response = build_reponse(&query, config, &sample).unwrap();
        assert_eq!(&response[..2], &[0xAB, 0xCD]);
        assert_eq!(&response[6..8], &1u16.to_be_bytes()); // ANCOUNT
        let mut reader = Cursor::new(response.as_slice());
        reader
            .seek(std::io::SeekFrom::Start(query.len() as u64))
            .unwrap();
        assert_eq!(decode_name(&mut reader).unwrap(), "seed.example.com");
        assert_eq!(read_u16_be(&mut reader).unwrap(), QType::A.0);
        assert_eq!(read_u16_be(&mut reader).unwrap(), QClass::IN.0);
        assert_eq!(read_u16_be(&mut reader).unwrap(), 0); // TTL high
        assert_eq!(read_u16_be(&mut reader).unwrap(), 60); // TTL low
        assert_eq!(read_u16_be(&mut reader).unwrap(), 4); // RDLENGTH
        assert_eq!(&response[response.len() - 4..], &[1, 2, 3, 4]);
    }

    #[test]
    fn rejects_truncated_name() {
        let mut reader = Cursor::new([4u8, b's', b'e'].as_slice());
        assert!(decode_name(&mut reader).is_err());
    }

    fn answers(response: &[u8], query_len: usize) -> (Cursor<&[u8]>, u16) {
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        let mut reader = Cursor::new(response);
        reader
            .seek(std::io::SeekFrom::Start(query_len as u64))
            .unwrap();
        (reader, ancount)
    }

    fn read_record(reader: &mut Cursor<&[u8]>) -> (String, u16, u16, u32, Vec<u8>) {
        let name = decode_name(reader).unwrap();
        let rtype = read_u16_be(reader).unwrap();
        let class = read_u16_be(reader).unwrap();
        let ttl = (read_u16_be(reader).unwrap() as u32) << 16 | read_u16_be(reader).unwrap() as u32;
        let len = read_u16_be(reader).unwrap() as usize;
        let start = reader.position() as usize;
        let rdata = reader.get_ref()[start..start + len].to_vec();
        reader.set_position((start + len) as u64);
        (name, rtype, class, ttl, rdata)
    }

    fn sample() -> Vec<IpAddr> {
        vec![
            "2001:db8::1".parse().unwrap(),
            "1.2.3.4".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
            "9.9.9.9".parse().unwrap(),
        ]
    }

    #[test]
    fn rejects_malformed_headers() {
        assert!(build_reponse(&[0u8; 11], test_config(), &[]).is_err());
        let mut no_questions = query(0x01, "seed.example.com", QType::A);
        no_questions[5] = 0;
        assert!(build_reponse(&no_questions, test_config(), &[]).is_err());
    }

    #[test]
    fn rejects_truncated_question() {
        let query = query(0x01, "seed.example.com", QType::A);
        for len in 12..query.len() {
            assert!(
                build_reponse(&query[..len], test_config(), &[]).is_err(),
                "{len}"
            );
        }
    }

    #[test]
    fn drops_non_internet_class() {
        let mut query = query(0x01, "seed.example.com", QType::A);
        let len = query.len();
        query[len - 1] = 3;
        assert!(build_reponse(&query, test_config(), &[]).is_err());
    }

    #[test]
    fn echoes_id_question_and_recursion_bit() {
        for (flags_high, expected) in [(0x00, 0x84), (0x01, 0x85)] {
            let query = query(flags_high, "seed.example.com", QType::A);
            let response = build_reponse(&query, test_config(), &[]).unwrap();
            assert_eq!(&response[..2], &[0xAB, 0xCD]);
            assert_eq!(response[2], expected);
            assert_eq!(response[3], 0x00);
            assert_eq!(&response[4..6], &1u16.to_be_bytes());
            assert_eq!(&response[12..query.len()], &query[12..]);
        }
    }

    #[test]
    fn matches_hostname_case_insensitively() {
        let query = query(0x01, "SeEd.ExAmPlE.cOm", QType::A);
        let response = build_reponse(&query, test_config(), &sample()).unwrap();
        assert_eq!(rcode_and_aa(&response), (0, true));
        assert_eq!(&response[6..8], &1u16.to_be_bytes());
    }

    #[test]
    fn a_query_returns_only_ipv4_up_to_limit() {
        let config = Configuration {
            query_answers: 2,
            ..test_config()
        };
        let query = query(0x01, "seed.example.com", QType::A);
        let response = build_reponse(&query, config, &sample()).unwrap();
        let (mut reader, ancount) = answers(&response, query.len());
        assert_eq!(ancount, 2);
        let mut ips = Vec::new();
        for _ in 0..ancount {
            let (name, rtype, class, ttl, rdata) = read_record(&mut reader);
            assert_eq!(
                (name.as_str(), rtype, class, ttl),
                ("seed.example.com", 1, 1, 60)
            );
            ips.push(rdata);
        }
        assert_eq!(ips, vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]]);
        assert_eq!(reader.position() as usize, response.len());
    }

    #[test]
    fn aaaa_query_returns_only_ipv6() {
        let config = Configuration {
            query_answers: 5,
            ..test_config()
        };
        let query = query(0x01, "seed.example.com", QType::AAAA);
        let response = build_reponse(&query, config, &sample()).unwrap();
        let (mut reader, ancount) = answers(&response, query.len());
        assert_eq!(ancount, 2);
        for expected in ["2001:db8::1", "2001:db8::2"] {
            let (_, rtype, _, _, rdata) = read_record(&mut reader);
            assert_eq!(rtype, QType::AAAA.0);
            let ip: std::net::Ipv6Addr = expected.parse().unwrap();
            assert_eq!(rdata, ip.octets());
        }
        assert_eq!(reader.position() as usize, response.len());
    }

    #[test]
    fn address_query_without_peers_is_empty_noerror() {
        for qtype in [QType::A, QType::AAAA] {
            let query = query(0x01, "seed.example.com", qtype);
            let response = build_reponse(&query, test_config(), &[]).unwrap();
            assert_eq!(rcode_and_aa(&response), (0, true));
            assert_eq!(&response[6..8], &0u16.to_be_bytes());
            assert_eq!(response.len(), query.len());
        }
    }

    #[test]
    fn soa_query_returns_zone_authority() {
        let query = query(0x01, "seed.example.com", QType::SOA);
        let response = build_reponse(&query, test_config(), &[]).unwrap();
        assert_eq!(rcode_and_aa(&response), (0, true));
        let (mut reader, ancount) = answers(&response, query.len());
        assert_eq!(ancount, 1);
        let (name, rtype, class, ttl, rdata) = read_record(&mut reader);
        assert_eq!(
            (name.as_str(), rtype, class, ttl),
            ("seed.example.com", 6, 1, 60)
        );
        assert_eq!(reader.position() as usize, response.len());
        let mut rdata = Cursor::new(rdata.as_slice());
        assert_eq!(decode_name(&mut rdata).unwrap(), "ns1.example.com");
        assert_eq!(decode_name(&mut rdata).unwrap(), "admin.example.com");
        let mut timers = Vec::new();
        for _ in 0..5 {
            let mut bytes = [0u8; 4];
            std::io::Read::read_exact(&mut rdata, &mut bytes).unwrap();
            timers.push(u32::from_be_bytes(bytes));
        }
        assert_eq!(timers, vec![1, 3600, 600, 86400, 60]);
        assert_eq!(rdata.position() as usize, rdata.get_ref().len());
    }

    #[test]
    fn ns_query_returns_nameserver() {
        let query = query(0x01, "seed.example.com", QType::NS);
        let response = build_reponse(&query, test_config(), &[]).unwrap();
        let (mut reader, ancount) = answers(&response, query.len());
        assert_eq!(ancount, 1);
        let (_, rtype, _, _, rdata) = read_record(&mut reader);
        assert_eq!(rtype, QType::NS.0);
        assert_eq!(
            decode_name(&mut Cursor::new(rdata.as_slice())).unwrap(),
            "ns1.example.com"
        );
        assert_eq!(reader.position() as usize, response.len());
    }

    #[test]
    fn ignores_additional_records() {
        let mut query = query(0x01, "seed.example.com", QType::A);
        let question_len = query.len();
        query[11] = 1;
        query.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        let response = build_reponse(&query, test_config(), &sample()).unwrap();
        assert_eq!(&response[10..12], &0u16.to_be_bytes());
        let (mut reader, ancount) = answers(&response, question_len);
        assert_eq!(ancount, 1);
        assert_eq!(read_record(&mut reader).4, vec![1, 2, 3, 4]);
        assert_eq!(reader.position() as usize, response.len());
    }

    #[test]
    fn nxdomain_and_refused_have_no_answers() {
        for name in ["a.b.seed.example.com", "example.org"] {
            let query = query(0x01, name, QType::A);
            let response = build_reponse(&query, test_config(), &sample()).unwrap();
            assert_eq!(&response[6..8], &0u16.to_be_bytes(), "{name}");
            assert_eq!(&response[12..], &query[12..], "{name}");
        }
    }

    #[test]
    fn largest_response_fits_in_udp_payload() {
        let v6: Vec<IpAddr> = (1..=10u16)
            .map(|i| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)))
            .collect();
        for qtype in [QType::AAAA, QType::SOA, QType::NS] {
            let config = Configuration {
                query_answers: 5,
                ..test_config()
            };
            let query = query(0x01, "seed.example.com", qtype);
            assert!(build_reponse(&query, config, &v6).unwrap().len() <= 512);
        }
    }
}
