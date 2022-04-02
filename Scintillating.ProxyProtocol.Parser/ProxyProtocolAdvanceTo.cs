namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// Describes the positions of processed/examined part of the incoming data sequence.
/// </summary>
/// <param name="Consumed">Position up to which parser consumed the data.</param>
/// <param name="Examined">Position up to which parser looked ahead and left the data as-is.</param>
public readonly record struct ProxyProtocolAdvanceTo(SequencePosition Consumed, SequencePosition Examined)
{
    /// <summary>
    /// Position up to which parser consumed the data.
    /// </summary>
    public SequencePosition Consumed { get; init; } = Consumed;

    /// <summary>
    /// Position up to which parser looked ahead and left the data as-is.
    /// </summary>
    public SequencePosition Examined { get; init; } = Examined;
}