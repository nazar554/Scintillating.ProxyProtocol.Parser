using System.Diagnostics;

namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// Application-Layer Protocol Negotiation (ALPN).
/// </summary>
public class ProxyProtocolTlvAlpn : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvAlpn"/> class.
    /// </summary>
    /// <param name="applicationProtocol"> The ALPN value.</param>
    public ProxyProtocolTlvAlpn(ReadOnlyMemory<byte> applicationProtocol)
        : base(ProxyProtocolTlvType.PP2_TYPE_ALPN, GetLength(applicationProtocol))
    {
        Value = applicationProtocol;
    }

    private static ushort GetLength(ReadOnlyMemory<byte> applicationProtocol)
    {
        int length = applicationProtocol.Length;
        Debug.Assert(length >= 0, nameof(length) + " is negative.");
        if (length == 0)
        {
            ParserThrowHelper.ThrowZeroByteAlpn();
        }
        return (ushort)length;
    }

    /// <summary>
    /// The ALPN value.
    /// </summary>
    public ReadOnlyMemory<byte> Value { get; }
}
