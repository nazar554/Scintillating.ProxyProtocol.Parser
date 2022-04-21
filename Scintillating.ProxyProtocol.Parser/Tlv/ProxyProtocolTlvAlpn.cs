using System.Net.Security;

namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// Application-Layer Protocol Negotiation (ALPN).
/// </summary>
public class ProxyProtocolTlvAlpn : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvAlpn"/> class.
    /// </summary>
    /// <param name="applicationProtocol"> The ALPN value.</param>
    public ProxyProtocolTlvAlpn(byte[] applicationProtocol)
        : base(ProxyProtocolTlvType.PP2_TYPE_ALPN, GetLength(applicationProtocol))
    {
        Value = new SslApplicationProtocol(applicationProtocol);
    }

    private static int GetLength(byte[] applicationProtocol)
    {
        int length = applicationProtocol.Length;
        if (length == 0)
        {
            ParserThrowHelper.ThrowZeroByteAlpn();
        }
        return length;
    }

    /// <summary>
    /// The ALPN value.
    /// </summary>
    public SslApplicationProtocol Value { get; }
}
