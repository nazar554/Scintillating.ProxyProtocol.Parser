using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

[StructLayout(LayoutKind.Explicit, Size = size)]
internal unsafe struct hdr
{
    public const int size = hdr_v2.size;

    [FieldOffset(0)]
    public hdr_v1 v1;

    [FieldOffset(0)]
    public hdr_v2 v2;
}
