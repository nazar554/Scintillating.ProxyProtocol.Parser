using System.Net;
using System.Net.Sockets;

namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// Describes the data parsed from PROXY protocol header.
/// </summary>
/// <param name="Version">The PROXY protocol version.</param>
/// <param name="Command">The command specified in PROXY protocol header.</param>
/// <param name="Length">The total length of PROXY protocol header.</param>
/// <param name="AddressFamily">The address family of source and destination endpoint.</param>
/// <param name="SocketType">The parsed socket type.</param>
/// <param name="Source">The source address.</param>
/// <param name="Destination">The destination address.</param>
/// <param name="TypeLengthValues">The collection of type length values.</param>
public record ProxyProtocolHeader(
    ProxyVersion Version,
    ProxyCommand Command,
    ushort Length,
    AddressFamily AddressFamily,
    SocketType SocketType,
    EndPoint? Source,
    EndPoint? Destination,
    IReadOnlyList<ProxyProtocolTlv>? TypeLengthValues = null
)
{
    /// <summary>
    /// The PROXY protocol version.
    /// </summary>
    public ProxyVersion Version { get; } = Version;

    /// <summary>
    /// The command specified in PROXY protocol header.
    /// </summary>
    public ProxyCommand Command { get; } = Command;

    /// <summary>
    /// The total length of PROXY protocol header.
    /// </summary>
    public ushort Length { get; } = Length;

    /// <summary>
    /// The address family of source and destination endpoint.
    /// </summary>
    public AddressFamily AddressFamily { get; } = AddressFamily;

    /// <summary>
    /// The parsed socket type.
    /// </summary>
    public SocketType SocketType { get; } = SocketType;

    /// <summary>
    /// The source address.
    /// </summary>
    public EndPoint? Source { get; } = Source;

    /// <summary>
    /// The destination address.
    /// </summary>
    public EndPoint? Destination { get; } = Destination;

    /// <summary>
    /// The collection of type length values.
    /// </summary>
    public IReadOnlyList<ProxyProtocolTlv> TypeLengthValues { get; } = TypeLengthValues ?? Array.Empty<ProxyProtocolTlv>();
}