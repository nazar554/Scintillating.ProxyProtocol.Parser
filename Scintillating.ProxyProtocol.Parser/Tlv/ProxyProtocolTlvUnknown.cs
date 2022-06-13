namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// TLV is used by a newer version of the PROXY protocol.
/// </summary>
public class ProxyProtocolTlvUnknown : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvUnknown"/> class.
    /// </summary>
    /// <param name="type">The type of this custom value.</param>
    /// <param name="value">The custom value.</param>
    public ProxyProtocolTlvUnknown(ProxyProtocolTlvType type, ReadOnlyMemory<byte> value)
        : base(type, value.Length)
    {
        Value = value;
    }

    /// <summary>
    /// The custom value.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; }
}