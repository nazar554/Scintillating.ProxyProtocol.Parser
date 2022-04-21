using System.Security.Cryptography;

namespace Scintillating.ProxyProtocol.Parser.Util;

internal sealed partial class Crc32C : HashAlgorithm
{
    private Hasher _hasher;
    public const int HashSizeBits = Hasher.SizeBits;

    public Crc32C()
    {
        HashSizeValue = Hasher.SizeBits;
        Initialize();
    }

    protected override void HashCore(byte[] array, int ibStart, int cbSize) => _hasher.HashCore(array, ibStart, cbSize);

    protected override void HashCore(ReadOnlySpan<byte> source) => _hasher.HashCore(source);

    protected override byte[] HashFinal() => _hasher.HashFinal();

    protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten) => _hasher.TryHashFinal(destination, out bytesWritten);

    public override void Initialize() => _hasher.Initialize();
}