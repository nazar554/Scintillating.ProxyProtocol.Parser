# Scintillating.ProxyProtocol.Parser

![Nuget](https://img.shields.io/nuget/v/Scintillating.ProxyProtocol.Parser)

**Scintillating.ProxyProtocol.Parser** is a .NET library for parsing [PROXY protocol](https://www.haproxy.org/download/2.6/doc/proxy-protocol.txt) headers.

## Quickstart

* The following example showcases how to use this library with `PipeReader`
* Note that `pipeReader.AdvanceTo` should be only called once per read, so any additional reading should happen before it.

```csharp

var cancellationToken = default(CancellationToken);
var pipe = new Pipe();
var pipeReader = pipe.Reader;
ProxyProtocolHeader? value = null;
var parser = new ProxyProtocolParser();
ReadResult readResult;
bool done = false;
do
{
    cancellationToken.ThrowIfCancellationRequested();
    readResult = await pipeReader.ReadAsync(cancellationToken)
        .ConfigureAwait(false);
    if (readResult.IsCanceled)
    {
        continue;
    }
    done = parser.TryParse(readResult.Buffer, out var advanceTo, out value);
    if (!done && readResult.IsCompleted)
    {
        throw new InvalidOperationException("Incomplete PROXY protocol header");
    }
    pipeReader.AdvanceTo(advanceTo.Consumed, advanceTo.Examined);
}
while (!done);
// use the value
_ = value;
```
