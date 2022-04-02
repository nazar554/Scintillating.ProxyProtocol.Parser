using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Sequential, Pack = 1, Size = size)]
internal unsafe struct ip6
{
    public const int size = addr_len * 2 * sizeof(byte) + sizeof(ushort) * 2;
    public const int addr_len = 16;

    public fixed byte src_addr[addr_len];
    public fixed byte dst_addr[addr_len];
    public ushort src_port;
    public ushort dst_port;
}
