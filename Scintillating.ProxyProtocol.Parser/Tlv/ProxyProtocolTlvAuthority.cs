namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// TLV contains the host name value passed by the client, as an UTF8-encoded string.
/// </summary>
public class ProxyProtocolTlvAuthority : ProxyProtocolTlv
{
    /// <summary>
    /// Maximum length of the authority field.
    /// </summary>
    public const int MaxLength = 255;

    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvAuthority"/> class.
    /// </summary>
    /// <param name="value">The authority value.</param>
    /// <param name="length">Length of UTF-8 encoded authority value.</param>
    public ProxyProtocolTlvAuthority(string value, int length)
        : base(ProxyProtocolTlvType.PP2_TYPE_AUTHORITY, length)
    {
        ArgumentNullException.ThrowIfNull(value);
        Value = value;
    }

    /// <summary>
    /// The authority value.
    /// </summary>
    public string Value { get; }
}
