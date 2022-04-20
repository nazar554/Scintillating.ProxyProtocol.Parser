namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// TLV is a 32-bit number storing the CRC32c checksum of the PROXY protocol header.
/// </summary>
public class ProxyProtocolTlvCRC32C : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvCRC32C"/> class.
    /// </summary>
    /// <param name="value">The CRC32c checksum of the PROXY protocol header, network byte order.</param>
    public ProxyProtocolTlvCRC32C(ReadOnlyMemory<byte> value)
        : base(ProxyProtocolTlvType.PP2_TYPE_CRC32C, GetLength(value))
    {
        Value = value;
    }

    private static int GetLength(ReadOnlyMemory<byte> value)
    {
        ParserUtility.Assert(value.Length >= 0);

        int length = value.Length;
        if (length != 4)
        {
            ParserThrowHelper.ThrowInvalidChecksum();
        }
        return length;
    }

    /// <summary>
    /// The CRC32c checksum of the PROXY protocol header, network byte order.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; }
}