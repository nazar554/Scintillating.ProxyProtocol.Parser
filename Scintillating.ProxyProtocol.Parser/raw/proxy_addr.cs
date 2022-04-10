using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Explicit)]
internal struct proxy_addr
{
    [FieldOffset(0)]
    public ip4 ip4;

    [FieldOffset(0)]
    public ip6 ip6;

    [FieldOffset(0)]
    public unix unix;
}
