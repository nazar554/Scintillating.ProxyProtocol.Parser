namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// TLV is reserved for temporary experimental use by application developers and protocol designers
/// </summary>
public class ProxyProtocolTlvExperiment : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvCustom"/> class.
    /// </summary>
    /// <param name="type">The type of this experimental value.</param>
    /// <param name="value">The experimental value.</param>
    public ProxyProtocolTlvExperiment(ProxyProtocolTlvType type, ReadOnlyMemory<byte> value)
        : base(type, value.Length)
    {
        Value = value;
    }

    /// <summary>
    /// The experimental value.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; }
}