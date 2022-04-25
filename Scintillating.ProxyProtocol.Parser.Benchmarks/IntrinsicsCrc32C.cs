using BenchmarkDotNet.Attributes;
using Scintillating.ProxyProtocol.Parser.Util;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Runtime.CompilerServices;

namespace Scintillating.ProxyProtocol.Parser.Benchmarks;

public unsafe class IntrinsicsCrc32C
{
    // [Params(100, 1000, 1024 * 1024, 100 * 1024 * 1024)]
    [Params(10 * 1024 * 1024)]
    public int N;

    private byte[] _data = null!;
    private byte* _ptr;

    [GlobalSetup]
    public void GlobalSetup()
    {
        if (Sse42.IsSupported)
        {
            RuntimeHelpers.RunClassConstructor(typeof(crc32_sse42).TypeHandle);
        }
        if (Crc32.IsSupported)
        {
            RuntimeHelpers.RunClassConstructor(typeof(pg_crc32c_armv8).TypeHandle);
        }
        RuntimeHelpers.RunClassConstructor(typeof(pg_crc32c_sb8).TypeHandle);

        var data = GC.AllocateUninitializedArray<byte>(N, pinned: true);
        Random.Shared.NextBytes(data);
        _data = data;
        fixed (byte* ptr = data)
        {
            _ptr = ptr;
        }
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        _ptr = null;
        _data = null!;
    }

    [Benchmark]
    public uint Intrinsics()
    {
        if (Sse42.IsSupported)
        {
            return crc32_sse42.sse42_crc32c(uint.MaxValue, _ptr, (nuint)N);
        }
        if (Crc32.IsSupported)
        {
            return pg_crc32c_armv8.pg_comp_crc32c_armv8(uint.MaxValue, _ptr, (nuint)N);
        }
        return Fallback();
    }

    [Benchmark(Baseline = true)]
    public uint Fallback() => pg_crc32c_sb8.pg_comp_crc32c_sb8(uint.MaxValue, _ptr, (nuint)N);
}