namespace Scintillating.ProxyProtocol.Parser;

/// <summary>
/// Thrown when error occurs during parsing
/// </summary>
[Serializable]
public class ProxyProtocolException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ProxyProtocolException"/> class.
    /// </summary>
    public ProxyProtocolException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ProxyProtocolException"/> class with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public ProxyProtocolException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ProxyProtocolException"/> class
    /// with a specified error message and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message">The error message that explains the reason for the exception.</param>
    /// <param name="inner">
    /// The exception that is the cause of the current exception, or a null reference
    /// (Nothing in Visual Basic) if no inner exception is specified.
    /// </param>
    public ProxyProtocolException(string message, Exception inner) : base(message, inner)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ProxyProtocolException"/> class with serialized data.
    /// </summary>
    /// <param name="info">
    /// The <see cref="System.Runtime.Serialization.SerializationInfo"/> that 
    /// holds the serialized object data about the exception being thrown.
    /// </param>
    /// <param name="context">
    /// The <see cref="System.Runtime.Serialization.StreamingContext"/> that
    /// contains contextual information about the source or destination.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="info"/> is null.</exception>
    /// <exception cref="System.Runtime.Serialization.SerializationException">The class name is null or <see cref="Exception.HResult"/> is zero (0).</exception>
    protected ProxyProtocolException(
      System.Runtime.Serialization.SerializationInfo info,
      System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
}