using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct hdr_v1
{
    // note that we it's not 108, since there is no null terminator
    public const int line_len = 107;

    public fixed byte line[line_len];
}
