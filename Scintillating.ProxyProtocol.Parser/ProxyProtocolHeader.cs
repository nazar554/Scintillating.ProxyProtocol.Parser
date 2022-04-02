using System.Net;
using System.Net.Sockets;

namespace Scintillating.ProxyProtocol.Parser;

public record ProxyProtocolHeader(
    ProxyVersion Version,
    ProxyCommand Command,
    ushort Length,
    AddressFamily AddressFamily,
    SocketType SocketType,
    EndPoint? Source,
    EndPoint? Destination
);