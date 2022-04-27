using BenchmarkDotNet.Running;

var assembly = typeof(Program).Assembly;
if (args.Length > 0)
{
    BenchmarkSwitcher.FromAssembly(assembly).Run(args);
}
else
{
    BenchmarkRunner.Run(assembly);
}