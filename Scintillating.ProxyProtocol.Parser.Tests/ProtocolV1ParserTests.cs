using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using System.Net.Sockets;
using System.Net;
using FluentAssertions.Execution;

namespace Scintillating.ProxyProtocol.Parser.Tests;

public class ProtocolV1ParserTests
{
    private ProxyProtocolParser _parser;

    [Fact]
    public void ShouldWorkWithMaxLineLengthTCP4()
    {
        var sequence = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".AsReadOnlyByteSequence();

        ProxyProtocolAdvanceTo advanceTo = default;
        ProxyProtocolHeader proxyProtocolHeader = null!;
        var func = () => _parser.TryParse(sequence, out advanceTo, out proxyProtocolHeader!);

        bool success = func.Should().NotThrow("input data is valid")
            .Subject;

        success.Should().BeTrue("input data is complete");
        advanceTo.Consumed.Should().Be(sequence.End, "input data is complete");
        advanceTo.Examined.Should().Be(sequence.End, "input data is complete");
        
        using (new AssertionScope(nameof(proxyProtocolHeader)))
        {
            proxyProtocolHeader.Should().NotBeNull("input data is complete");

            proxyProtocolHeader!.Version.Should()
                .Be(ProxyVersion.V1, "testing human-readable protocol");
            proxyProtocolHeader!.Command.Should()
                .Be(ProxyCommand.Proxy, "there is a single command in protocol V1");
            proxyProtocolHeader!.Length.Should()
                .Be((ushort)sequence.Length, "entire header has to be consumed");

            proxyProtocolHeader!.AddressFamily.Should()
                .Be(AddressFamily.InterNetwork, "example uses TCP4");
            proxyProtocolHeader!.SocketType.Should()
                .Be(SocketType.Stream, "example uses TCP4");

            proxyProtocolHeader!.Source.Should()
                .NotBeNull("example has source address and port");
            proxyProtocolHeader!.Source.Should()
                .Be(IPEndPoint.Parse("255.255.255.255:65535"), "source endpoint and port should match");

            proxyProtocolHeader!.Destination.Should()
                .NotBeNull("example has destination address and port");
            proxyProtocolHeader!.Destination.Should()
                .Be(IPEndPoint.Parse("255.255.255.255:65535"), "destination endpoint and port should match");
        }
    }
}
