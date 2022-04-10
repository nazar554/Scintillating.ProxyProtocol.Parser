namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// TLV is reserved for application-specific data and will be never used by the PROXY Protocol.
/// </summary>
public class ProxyProtocolTlvCustom : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvCustom"/> class.
    /// </summary>
    /// <param name="type">The type of this custom value.</param>
    /// <param name="value">The custom value.</param>
    public ProxyProtocolTlvCustom(ProxyProtocolTlvType type, ReadOnlyMemory<byte> value)
        : base(type, value.Length)
    {
        Value = value;
    }

    /// <summary>
    /// The custom value.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; }
}