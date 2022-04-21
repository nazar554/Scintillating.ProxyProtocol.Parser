namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// TLV is a 32-bit number storing the CRC32c checksum of the PROXY protocol header.
/// </summary>
public class ProxyProtocolTlvCRC32C : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvCRC32C"/> class.
    /// </summary>
    /// <param name="value">The CRC32c checksum of the PROXY protocol header.</param>
    public ProxyProtocolTlvCRC32C(uint value)
        : base(ProxyProtocolTlvType.PP2_TYPE_CRC32C, Util.Crc32C.Hasher.SizeBits / 8)
    {
        Value = value;
    }


    /// <summary>
    /// The CRC32c checksum of the PROXY protocol header.
    /// </summary>
    public uint Value { get; }
}