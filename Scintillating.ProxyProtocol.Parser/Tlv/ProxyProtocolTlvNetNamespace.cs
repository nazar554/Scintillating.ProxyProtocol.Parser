namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// TLV defines the value as the US-ASCII string representation of the namespace's name.
/// </summary>
public class ProxyProtocolTlvNetNamespace : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvNetNamespace"/> class.
    /// </summary>
    /// <param name="value">The namespace's name.</param>
    public ProxyProtocolTlvNetNamespace(string value)
        : base(ProxyProtocolTlvType.PP2_TYPE_NETNS, value is not null ? value.Length : throw new ArgumentNullException(nameof(value)))
    {
        Value = value;
    }

    /// <summary>
    /// The namespace's name.
    /// </summary>
    public string Value { get; }
}