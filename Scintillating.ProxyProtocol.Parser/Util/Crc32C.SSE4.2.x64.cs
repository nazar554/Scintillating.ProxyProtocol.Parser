﻿using System.Runtime.CompilerServices;
using Sse42 = System.Runtime.Intrinsics.X86.Sse42;

namespace Scintillating.ProxyProtocol.Parser.Util;

internal sealed partial class Crc32C
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint HashCoreImplSse42x64(uint crc, ref byte data, nuint length)
    {
        while (length >= sizeof(ulong))
        {
            crc = (uint)Sse42.X64.Crc32(crc, Unsafe.ReadUnaligned<ulong>(ref data));
            data = ref Unsafe.Add(ref data, sizeof(ulong));
            length -= sizeof(ulong);
        }
        if ((length & sizeof(uint)) != 0)
        {
            crc = Sse42.Crc32(crc, Unsafe.ReadUnaligned<uint>(ref data));
            data = ref Unsafe.Add(ref data, sizeof(uint));
        }
        if ((length & sizeof(ushort)) != 0)
        {
            crc = Sse42.Crc32(crc, Unsafe.ReadUnaligned<ushort>(ref data));
            data = ref Unsafe.Add(ref data, sizeof(ushort));
        }
        if ((length & sizeof(byte)) != 0)
        {
            crc = Sse42.Crc32(crc, data);
        }
        return crc;
    }
}