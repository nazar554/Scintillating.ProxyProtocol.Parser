using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Explicit, Size = size)]
internal struct proxy_addr
{
    public const int size = unix.size;

    [FieldOffset(0)]
    public ip4 ip4;

    [FieldOffset(0)]
    public ip6 ip6;

    [FieldOffset(0)]
    public unix unix;
}
