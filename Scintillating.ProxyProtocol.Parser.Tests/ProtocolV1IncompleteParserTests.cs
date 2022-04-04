using Xunit;
using FluentAssertions;
using System.Net.Sockets;
using System.Net;
using FluentAssertions.Execution;
using System.Buffers;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class ProtocolV1IncompleteParserTests
{
    private ProxyProtocolParser _parser;

    [Fact]
    public void ShouldIgnoreIncompleteV1Data()
    {
        var sequence = "PROXY ".AsReadOnlyByteSequence();

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        bool success = func.Should().NotThrow("input data is valid, but incomplete").Subject;
        success.Should().BeFalse("input data is incomplete");
        proxyProtocolHeader.Should().BeNull();

        sequence.GetOffset(advanceTo.Consumed).Should().Be(0, "input data is incomplete");
        sequence.GetOffset(advanceTo.Examined).Should().Be(sequence.Length, "input data is complete");
    }


    [Fact]
    public void ShouldThrowOnInvalidIncompleteV1Data()
    {
        var sequence = "IND? ".AsReadOnlyByteSequence();

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        func.Should().ThrowExactly<ProxyProtocolException>("input data is invalid");
        proxyProtocolHeader.Should().BeNull();
        advanceTo.Consumed.Should().Be(default(SequencePosition));
        advanceTo.Examined.Should().Be(default(SequencePosition));
    }
}
