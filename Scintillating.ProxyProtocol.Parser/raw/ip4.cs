using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct ip4
{
    public uint src_addr;
    public uint dst_addr;
    public ushort src_port;
    public ushort dst_port;
}
