using System.Runtime.InteropServices;

namespace Scintillating.ProxyProtocol.Parser.raw;

/// <summary>
/// The PROXY protocol header
/// </summary>
[StructLayout(LayoutKind.Explicit)]
internal unsafe struct proxy_hdr
{
    /// <summary>
    /// Human-readable header format (Version 1)
    /// </summary>
    [FieldOffset(0)]
    public proxy_hdr_v1 v1;

    /// <summary>
    /// Binary header format (version 2)
    /// </summary>
    [FieldOffset(0)]
    public proxy_hdr_v2 v2;
}
