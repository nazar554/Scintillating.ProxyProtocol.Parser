namespace Scintillating.ProxyProtocol.Parser.Tlv;

/// <summary>
/// The TLV describes connections's TLS/SSL options.
/// </summary>
public class ProxyProtocolTlvSsl : ProxyProtocolTlv
{
    /// <summary>
    /// Constructs a new instance of <see cref="ProxyProtocolTlvSsl"/> class.
    /// </summary>
    /// <param name="flags">Flags that describe TLS/SSL connection.</param>
    /// <param name="verify">Indicates if the client presented a certificate and it was successfully verified.</param>
    /// <param name="version">The version of SSL/TLS protocol used.</param>
    /// <param name="cipher">The name of used SSL/TLS cipher.</param>
    /// <param name="serverSignatureAlgorithm">The name of signature algorithm used by the server certificate.</param>
    /// <param name="serverKeyAlgorithm">The name of key algorithm used by the server certificate.</param>
    /// <param name="clientCN">The "Common Name" field (CN, OID: 2.5.4.3) of the client certificate.</param>
    /// <param name="length">The length of the TLV.</param>
    public ProxyProtocolTlvSsl(ProxyProtocolTlvFlags flags, bool verify, string? version,
        string? cipher, string? serverSignatureAlgorithm, string? serverKeyAlgorithm, string? clientCN, int length)
        : base(ProxyProtocolTlvType.PP2_TYPE_SSL, length)
    {
        Flags = flags;
        Verify = verify;
        Version = version;
        Cipher = cipher;
        ServerSignatureAlgorithm = serverSignatureAlgorithm;
        ClientCN = clientCN;
        ServerKeyAlgorithm = serverKeyAlgorithm;
    }

    /// <summary>
    /// Flags that describe TLS/SSL connection.
    /// </summary>
    public ProxyProtocolTlvFlags Flags { get; }

    /// <summary>
    /// Indicates if the client presented a certificate and it was successfully verified.
    /// </summary>
    public bool Verify { get; }

    /// <summary>
    /// The version of SSL/TLS protocol used.
    /// </summary>
    public string? Version { get; }

    /// <summary>
    /// The name of used SSL/TLS cipher.
    /// </summary>
    public string? Cipher { get; }

    /// <summary>
    /// The name of signature algorithm used by the server certificate.
    /// </summary>
    public string? ServerSignatureAlgorithm { get; }

    /// <summary>
    /// The name of key algorithm used by the server certificate.
    /// </summary>
    public string? ServerKeyAlgorithm { get; }

    /// <summary>
    /// The "Common Name" field (CN, OID: 2.5.4.3) of the client certificate.
    /// </summary>
    public string? ClientCN { get; }
}