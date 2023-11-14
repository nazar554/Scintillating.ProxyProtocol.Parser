// Adapted from PostgreSQL project
// See postgres/src/port/pg_crc32c_armv8.c

/*-------------------------------------------------------------------------
 *
 * pg_crc32c_armv8.c
 *	  Compute CRC-32C checksum using ARMv8 CRC Extension instructions
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/port/pg_crc32c_armv8.c
 *
 *-------------------------------------------------------------------------
 */

using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using Crc32 = System.Runtime.Intrinsics.Arm.Crc32;
using pg_crc32c = System.UInt32;
using uint16 = System.UInt16;
using uint32 = System.UInt32;
using uint64 = System.UInt64;

namespace Scintillating.ProxyProtocol.Parser.Util;

[ExcludeFromCodeCoverage(Justification = "ARMv8 CRC32C is machine dependent.")]
internal static class pg_crc32c_armv8
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe bool PointerIsAligned(void* pointer, nuint len)
    {
        return ((nuint)pointer % len) == 0;
    }

    public static unsafe pg_crc32c pg_comp_crc32c_armv8(pg_crc32c crc, byte* data, nuint len)
    {
        byte* p = data;
        byte* pend = data + len;

        /*
         * ARMv8 doesn't require alignment, but aligned memory access is
         * significantly faster. Process leading bytes so that the loop below
         * starts with a pointer aligned to eight bytes.
         */
        if (!PointerIsAligned(p, sizeof(uint16)) && p + 1 <= pend)
        {
            crc = Crc32.ComputeCrc32C(crc, *p);
            p += 1;
        }
        if (!PointerIsAligned(p, sizeof(uint32)) && p + 2 <= pend)
        {
            crc = Crc32.ComputeCrc32C(crc, *(uint16*)p);
            p += 2;
        }

        if (Crc32.Arm64.IsSupported)
        {
            if (!PointerIsAligned(p, sizeof(uint64)) && p + 4 <= pend)
            {
                crc = Crc32.ComputeCrc32C(crc, *(uint32*)p);
                p += 4;
            }

            /* Process eight bytes at a time, as far as we can. */
            while (p + 8 <= pend)
            {
                crc = Crc32.Arm64.ComputeCrc32C(crc, *(uint64*)p);
                p += 8;
            }

            /* Process remaining 0-7 bytes. */
            if (p + 4 <= pend)
            {
                crc = Crc32.ComputeCrc32C(crc, *(uint32*)p);
                p += 4;
            }
        }
        else
        {
            /* Process four bytes at a time, as far as we can. */
            while (p + 4 <= pend)
            {
                crc = Crc32.ComputeCrc32C(crc, *(uint32*)p);
                p += 4;
            }
        }

        if (p + 2 <= pend)
        {
            crc = Crc32.ComputeCrc32C(crc, *(uint16*)p);
            p += 2;
        }
        if (p < pend)
        {
            crc = Crc32.ComputeCrc32C(crc, *p);
        }

        return crc;
    }
}