using System.Net.Security;

namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// Application-Layer Protocol Negotiation (ALPN).
/// </summary>
public class ProxyProtocolTlvAlpn : ProxyProtocolTlv, IEquatable<ProxyProtocolTlvAlpn?>
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

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as ProxyProtocolTlvAlpn);
    }

    /// <inheritdoc/>
    public bool Equals(ProxyProtocolTlvAlpn? other)
    {
        return other is not null && Value.Equals(other.Value);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Type, Length, Value);
    }

    /// <summary>
    /// The ALPN value.
    /// </summary>
    public SslApplicationProtocol Value { get; }

    /// <inheritdoc/>
    public static bool operator ==(ProxyProtocolTlvAlpn? left, ProxyProtocolTlvAlpn? right)
    {
        return EqualityComparer<ProxyProtocolTlvAlpn>.Default.Equals(left, right);
    }

    /// <inheritdoc/>
    public static bool operator !=(ProxyProtocolTlvAlpn? left, ProxyProtocolTlvAlpn? right)
    {
        return !(left == right);
    }
}
