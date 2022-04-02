namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// Describes the PROXY protocol header version.
/// </summary>
public enum ProxyVersion : byte
{
    /// <summary>
    /// Human-readable header format (Version 1)
    /// </summary>
    V1 = 0x1,

    /// <summary>
    /// Binary header format (version 2)
    /// </summary>
    V2 = 0x2
}