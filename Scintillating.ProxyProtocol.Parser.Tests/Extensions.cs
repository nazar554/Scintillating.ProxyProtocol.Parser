using System.Buffers;
using System.Text;

namespace Scintillating.ProxyProtocol.Parser.Tests;

internal static class Extensions
{
    public static ReadOnlySequence<byte> AsReadOnlyByteSequence(this string value, Encoding? encoding = null)
    {
        byte[] bytes = (encoding ?? Encoding.ASCII).GetBytes(value);

        return new ReadOnlySequence<byte>(bytes);
    }
}