using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Sequential, Pack = 1, Size = size)]
internal unsafe struct unix
{
    public const int addr_len = 108;
    public const int size = addr_len * 2 * sizeof(byte);

    public fixed byte src_addr[addr_len];
    public fixed byte dst_addr[addr_len];
}
