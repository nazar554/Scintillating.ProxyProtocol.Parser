namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// Represents a single type length value (base class).
/// </summary>
public abstract class ProxyProtocolTlv
{
    /// <summary>
    /// Construct an instance of <see cref="ProxyProtocolTlv"/>.
    /// </summary>
    /// <param name="type">Type of the value.</param>
    /// <param name="length">Length of the value.</param>
    protected ProxyProtocolTlv(ProxyProtocolTlvType type, ushort length)
    {
        Type = type;
        Length = length;
    }

    /// <summary>
    /// Type of the value.
    /// </summary>
    public ProxyProtocolTlvType Type { get; }

    /// <summary>
    /// Length of the value in bytes.
    /// </summary>
    public ushort Length { get; }
}
