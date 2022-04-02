using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Sequential, Pack = 1, Size = size)]
internal unsafe struct hdr_v2
{
    public const int size = sig_len * sizeof(byte) + sizeof(byte) * 2 + sizeof(ushort) + proxy_addr.size;
    public const int sig_len = 12;

    public fixed byte sig[sig_len];
    public byte ver_cmd;
    public byte fam;
    public ushort len;
    public proxy_addr proxy_addr;
}
