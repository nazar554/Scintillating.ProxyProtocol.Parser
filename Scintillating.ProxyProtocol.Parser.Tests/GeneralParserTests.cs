using Xunit;
using System.Buffers;

using FluentAssertions;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class GeneralParserTests
{
    private ProxyProtocolParser _parser;

    [Fact]
    public void ShouldNotConsumePartialInputV1()
    {
        var sequence = "PRO".AsReadOnlyByteSequence();

        bool success = _parser.TryParse(sequence, out var advanceTo, out var proxyProtocolHeader);

        success.Should().BeFalse("it's a partial input");
        advanceTo.Consumed.Should().Be(sequence.Start, "no data is consumed for partial input");
        advanceTo.Examined.Should().Be(sequence.End, "whole sequence must be examined");
        proxyProtocolHeader.Should().BeNull("it's a partial input");
    }

    [Fact]
    public void ShouldNotConsumePartialInputV2()
    {
        var sequence = new ReadOnlySequence<byte>(ParserConstants.SigV2.ToArray());

        bool success = _parser.TryParse(sequence, out var advanceTo, out var proxyProtocolHeader);

        success.Should().BeFalse("it's a partial input");
        advanceTo.Consumed.Should().BeEquivalentTo(sequence.Start, "no data is consumed for partial input");
        advanceTo.Examined.Should().BeEquivalentTo(sequence.End, "whole sequence must be examined");
        proxyProtocolHeader.Should().BeNull("it's a partial input");
    }

    [Fact]
    public void ShouldNotConsumePartialInputV1BetweenV2()
    {
        var sequence = new ReadOnlySequence<byte>(ParserConstants.SigV2[..9].ToArray());

        bool success = _parser.TryParse(sequence, out var advanceTo, out var proxyProtocolHeader);

        success.Should().BeFalse("it's a partial input");
        advanceTo.Consumed.Should().BeEquivalentTo(sequence.Start, "no data is consumed for partial input");
        advanceTo.Examined.Should().BeEquivalentTo(sequence.End, "whole sequence must be examined");
        proxyProtocolHeader.Should().BeNull("it's a partial input");
    }

    [Fact]
    public void ShouldThrowOnInvalidPartialV2Header()
    {
        var bytes = ParserConstants.SigV2[..9].ToArray();
        bytes[5] = 0xFF;
        var sequence = new ReadOnlySequence<byte>(bytes);

        Action action = () =>
        {
            _ = _parser.TryParse(sequence, out _, out _);
        };
        action.Should().ThrowExactly<ProxyProtocolException>("passed invalid input");
    }

    [Fact]
    public void ShouldThrowOnInvalidV2Header()
    {
        var sig = ParserConstants.SigV2;
        var bytes = new byte[16];
        sig.CopyTo(bytes);
        bytes[sig.Length] = 0xFF;

        var sequence = new ReadOnlySequence<byte>(bytes);

        Action action = () =>
        {
            _ = _parser.TryParse(sequence, out _, out _);
        };
        action.Should().ThrowExactly<ProxyProtocolException>("passed invalid input");
    }

    [Fact]
    public void ShouldThrowOnInvalidInput()
    {
        var sequence = "INVALID INPUT".AsReadOnlyByteSequence();

        Action action = () =>
        {
            _ = _parser.TryParse(sequence, out _, out _);
        };
        action.Should().ThrowExactly<ProxyProtocolException>("passed invalid input");
    }

    [Fact]
    public void ShouldAlwaysThrowAfterInvalidInput()
    {
        var sequence = "INVALID INPUT".AsReadOnlyByteSequence();

        Action action = () =>
        {
            _ = _parser.TryParse(sequence, out _, out _);
        };
        action.Should().ThrowExactly<ProxyProtocolException>("passed invalid input");

        sequence = "PROXY UNKNOWN\r\n".AsReadOnlyByteSequence();
        action = () =>
        {
            _ = _parser.TryParse(sequence, out _, out _);
        };
        action.Should().ThrowExactly<ProxyProtocolException>("didn't reset");
    }

    [Fact]
    public void ShouldNotThrowAfterReset()
    {
        var sequence = "INVALID INPUT".AsReadOnlyByteSequence();

        Action action = () =>
        {
            _ = _parser.TryParse(sequence, out _, out _);
        };
        action.Should().ThrowExactly<ProxyProtocolException>("passed invalid input");

        action = () =>
        {
            _parser.Reset();
        };
        action.Should().NotThrow("reset should always succeed");

        sequence = "PROXY UNKNOWN\r\n".AsReadOnlyByteSequence();

        action = () =>
        {
            _ = _parser.TryParse(sequence, out _, out _);
        };
        action.Should().NotThrow("we did reset the parser");
    }
}
