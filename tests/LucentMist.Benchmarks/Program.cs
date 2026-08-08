using BenchmarkDotNet.Running;
using LucentMist.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
