namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// Flags that describe SSL connection in <see cref="ProxyProtocolTlvSsl"/>.
/// </summary>
[Flags]
public enum ProxyProtocolTlvFlags : byte
{
    /// <summary>
    /// Indicates that the client connected over SSL/TLS.
    /// <para>
    /// When this field is present, the US-ASCII string representation of the TLS version is
    /// appended at the end of the field in the TLV format using the type <see cref="ProxyProtocolTlvType.PP2_SUBTYPE_SSL_VERSION"/>.
    /// </para>
    /// </summary>
    PP2_CLIENT_SSL = 0x01,

    /// <summary>
    /// Indicates that the client provided a certificate over the current connection.
    /// </summary>
    PP2_CLIENT_CERT_CONN = 0x02,

    /// <summary>
    /// Indicates that the client provided a certificate at least once over the TLS session this connection belongs to.
    /// </summary>
    PP2_CLIENT_CERT_SESS = 0x04,
}