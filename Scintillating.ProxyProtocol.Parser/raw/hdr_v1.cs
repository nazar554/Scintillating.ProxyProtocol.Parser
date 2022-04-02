using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Sequential, Pack = 1, Size = size)]
internal unsafe struct hdr_v1
{
    public const int line_len = 108;
    public const int size = line_len * sizeof(byte);

    public fixed byte line[line_len];
}
