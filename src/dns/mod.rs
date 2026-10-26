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

struct Id(u16);

impl Id {
    fn from_be_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

struct QType;

impl QType {
    const A: u16 = 1;
    const NS: u16 = 2;
    const SOA: u16 = 6;
    const AAAA: u16 = 28;
}

struct QClass;

impl QClass {
    const IN: u16 = 1;
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
    const NoError: Self = Self(0);
    const NoDomain: Self = Self(3);
}

struct Flags(u16);

impl Flags {
    fn new(recursion: RecursionBit, response_code: ResponseCode) -> Self {
        // QR = response | AA | echo recursion bit | response code
        Self(0x8000 | 0x0400 | recursion.flag() | response_code.0)
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
}

fn build_reponse(mut data: &[u8]) -> std::io::Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Query must be at least 12 bytes.",
        ));
    }
    let id = Id::from_be_bytes([data[0], data[1]]);
    let recurse_bit = RecursionBit::new(data[2]);
    let qcount = u16::from_be_bytes([data[4], data[5]]);
    if qcount == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "QCount is empty.",
        ));
    }
    Ok(Vec::new())
}
