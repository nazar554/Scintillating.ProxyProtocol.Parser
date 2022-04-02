namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// The lowest four bits of <see cref="raw.hdr_v2.ver_cmd"/> represent the command
/// </summary>
/// <remarks>
/// Other values are unassigned and must not be emitted by senders. Receivers must drop connections presenting unexpected values here.
/// </remarks>
public enum ProxyCommand : byte
{
    /// <summary>
    /// LOCAL: the connection was established on purpose by the proxy
    /// </summary>
    /// <remarks>
    /// <para>
    /// The connection endpoints are the sender and the receiver.
    /// Such connections exist when the proxy sends health-checks to the server.
    /// </para>
    /// <para>
    /// The receiver must accept this connection as valid and must use the
    /// real connection endpoints and discard the protocol block including the
    /// family which is ignored.
    /// </para>
    /// </remarks>
    Local = 0x0,

    /// <summary>
    /// PROXY: the connection was established on behalf of another node,
    /// </summary>
    /// <remarks>
    /// <para>The connection was established on behalf of another node, and reflects the original connection endpoints</para>
    /// <para>The receiver must then use the information provided in the protocol block to get original the address.</para>
    /// </remarks>
    Proxy = 0x1
}
