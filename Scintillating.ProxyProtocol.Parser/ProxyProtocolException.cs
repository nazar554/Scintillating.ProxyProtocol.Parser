namespace Scintillating.ProxyProtocol.Parser;

[Serializable]
public class ProxyProtocolException : Exception
{
    public ProxyProtocolException()
    {
    }

    public ProxyProtocolException(string message) : base(message)
    {
    }

    public ProxyProtocolException(string message, Exception inner) : base(message, inner)
    {
    }

    protected ProxyProtocolException(
      System.Runtime.Serialization.SerializationInfo info,
      System.Runtime.Serialization.StreamingContext context) : base(info, context) { }
}