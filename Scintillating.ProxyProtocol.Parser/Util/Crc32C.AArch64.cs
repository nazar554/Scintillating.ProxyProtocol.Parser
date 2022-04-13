using System.Runtime.CompilerServices;
using Crc32 = System.Runtime.Intrinsics.Arm.Crc32;

namespace Scintillating.ProxyProtocol.Parser.Util;

internal sealed partial class Crc32C
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint HashCoreImplAarch64(uint crc, ref byte data, nuint length)
    {
        while (length >= sizeof(ulong))
        {
            crc = Crc32.Arm64.ComputeCrc32C(crc, Unsafe.ReadUnaligned<ulong>(ref data));
            data = ref Unsafe.Add(ref data, sizeof(ulong));
            length -= sizeof(ulong);
        }
        if ((length & sizeof(uint)) != 0)
        {
            crc = Crc32.ComputeCrc32C(crc, Unsafe.ReadUnaligned<uint>(ref data));
            data = ref Unsafe.Add(ref data, sizeof(uint));
        }
        if ((length & sizeof(ushort)) != 0)
        {
            crc = Crc32.ComputeCrc32C(crc, Unsafe.ReadUnaligned<ushort>(ref data));
            data = ref Unsafe.Add(ref data, sizeof(ushort));
        }
        if ((length & sizeof(byte)) != 0)
        {
            crc = Crc32.ComputeCrc32C(crc, data);
        }
        return crc;
    }
}