using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct af_unix
{
    public const int addr_len = 108;

    public fixed byte src_addr[addr_len];
    public fixed byte dst_addr[addr_len];
}
