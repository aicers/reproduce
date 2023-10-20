use num_enum::FromPrimitive;
use strum_macros::EnumString;

#[derive(Copy, Clone, Debug, EnumString, FromPrimitive, PartialEq)]
#[repr(u16)]
pub enum FieldTypes {
    InBytes = 1,
    InPackets = 2,
    Flows = 3,
    Protocol = 4,
    SrcTos = 5,
    TCPFlags = 6,
    L4SrcPort = 7,
    IPv4SrcAddr = 8,
    SrcMask = 9,
    InputSNMP = 10,
    L4DstPort = 11,
    IPv4DstAddr = 12,
    DstMask = 13,
    OutputSNMP = 14,
    IPv4NextHop = 15,
    SrcAS = 16,
    DstAS = 17,
    BgpIPv4NextHop = 18,
    MulDstPackets = 19,
    MulDstBytes = 20,
    LastSwitched = 21,
    FirstSwitched = 22,
    OutBytes = 23,
    OutPackets = 24,
    MinPktLength = 25,
    MaxPktLength = 26,
    IPv6SrcAddr = 27,
    IPv6DstAddr = 28,
    IPv6SrcMask = 29,
    IPv6DstMask = 30,
    IPv6FlowLabel = 31,
    ICMPType = 32,
    MulIGMPType = 33,
    SamplingInterval = 34,
    SamplingAlgorithm = 35,
    FlowActiveTimeout = 36,
    FlowInactiveTimeout = 37,
    EngineType = 38,
    EngineID = 39,
    TotalBytesExp = 40,
    TotalPacketsExp = 41,
    TotalFlowsExp = 42,
    IPv4SrcPrefix = 44,
    IPv4DstPrefix = 45,
    MPLSTopLabelType = 46,
    MPLSTopLabelIPAddr = 47,
    FlowSamplerID = 48,
    FlowSamplerMode = 49,
    FlowSamplerRandomInterval = 50,
    MinTTL = 52,
    MaxTTL = 53,
    IPv4Ident = 54,
    DstTos = 55,
    InSrcMac = 56,
    OutDstMac = 57,
    SrcVLAN = 58,
    DstVLAN = 59,
    IPProtocolVersion = 60,
    Direction = 61,
    IPv6NextHop = 62,
    BgpIPv6NextHop = 63,
    IPv6OptionHeaders = 64,
    MPLSLabel1 = 70,
    MPLSLabel2 = 71,
    MPLSLabel3 = 72,
    MPLSLabel4 = 73,
    MPLSLabel5 = 74,
    MPLSLabel6 = 75,
    MPLSLabel7 = 76,
    MPLSLabel8 = 77,
    MPLSLabel9 = 78,
    MPLSLabel10 = 79,
    InDstMAC = 80,
    OutSrcMAC = 81,
    IfName = 82,
    IfDesc = 83,
    SamplerName = 84,
    InPermanentBytes = 85,
    InPermanentPackets = 86,
    FragmentOffset = 88,
    ForwardingStatus = 89,
    MPLSPalRd = 90,
    MPLSPrefixLen = 91,
    SrcTrafficIndex = 92,
    DstTrafficIndex = 93,
    ApplicationDescription = 94,
    ApplicationTag = 95,
    ApplicationName = 96,
    PostIPDiffServCodePoint = 98,
    ReplicationFactor = 99,
    Layer2PacketSectionOffset = 102,
    Layer2PacketSectionData = 103,
    IngressVRFID = 234,
    EgressVRFID = 235,
    #[num_enum(default)]
    Unknown = u16::MAX,
}

impl FieldTypes {
    pub fn get_types(self) -> DataTypes {
        match self {
            FieldTypes::TCPFlags => DataTypes::TcpFlags,
            FieldTypes::IPv4SrcAddr
            | FieldTypes::IPv4DstAddr
            | FieldTypes::IPv4NextHop
            | FieldTypes::BgpIPv4NextHop
            | FieldTypes::IPv4SrcPrefix
            | FieldTypes::IPv4DstPrefix
            | FieldTypes::MPLSTopLabelIPAddr => DataTypes::Ipv4,
            FieldTypes::IPv6SrcAddr
            | FieldTypes::IPv6DstAddr
            | FieldTypes::IPv6NextHop
            | FieldTypes::BgpIPv6NextHop => DataTypes::Ipv6,
            FieldTypes::ForwardingStatus => DataTypes::ForwardingStatus,
            FieldTypes::IfDesc | FieldTypes::SamplerName => DataTypes::Text,
            _ => DataTypes::Integer,
        }
    }
}

#[derive(PartialEq)]
pub enum DataTypes {
    Ascii,
    ForwardingStatus,
    Integer,
    Ipv4,
    Ipv6,
    TcpFlags,
    Text,
}

#[derive(Copy, Clone, Debug, EnumString, FromPrimitive, PartialEq)]
#[repr(u16)]
pub enum OptionsScopeFieldTypes {
    System = 1,
    Interface = 2,
    LineCard = 3,
    NetflowCache = 4,
    Template = 5,
    #[num_enum(default)]
    Unknown = u16::MAX,
}

// FORWARDING STATUS. 1Byte: Status(2bit) + ReasonCode(6bit)
pub static FORWARDING_STATUS: [(u8, &str); 24] = [
    (0, "Unknown"),
    (64, "Forwarded (Unknown)"),
    (65, "Forwarded (Fragmented)"),
    (66, "Forwarded (Not Fragmented)"),
    (128, "Dropped (Unknown)"),
    (129, "Dropped (ACL Deny)"),
    (130, "Dropped (ACL Drop)"),
    (131, "Dropped (Unroutable)"),
    (132, "Dropped (Adjacency)"),
    (133, "Dropped (Fragmentation & DF set)"),
    (134, "Dropped (Bad Header Checksum)"),
    (135, "Dropped (Bad Total Length)"),
    (136, "Dropped (Bad Header Length)"),
    (137, "Dropped (Bad TTL)"),
    (138, "Dropped (Policer)"),
    (139, "Dropped (WRED)"),
    (140, "Dropped (RPF)"),
    (141, "Dropped (For us)"),
    (142, "Dropped (Bad Output Interface)"),
    (143, "Dropped (Hardware)"),
    (192, "Consumed (Unknown)"),
    (193, "Consumed (Terminate Punt Adjacency)"),
    (194, "Consumed (Terminate Incomplete Adjacency)"),
    (195, "Consumed (Terminate For us)"),
];

pub static TCP_FLAGS: [(u8, &str); 8] = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x08, "CWR"),
];
