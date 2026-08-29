# Performance Validation

These measurements are deterministic orchestration tests with simulated work. They
measure scheduling and concurrency bounds, not real-network throughput. Real scan
time still depends on timeouts, target responsiveness, host resources, and network
policy.

## Report device collection

Date: 2026-08-30
Test: `ReportDeviceCollectorTests.CollectAsync_TenDevices_IsBoundedAndFasterThanSequential`

Ten simulated devices each required 100 ms of asynchronous collection work. The
same work was measured sequentially and through the production bounded collector
with maximum concurrency 4:

```text
sequential=1106 ms
bounded-parallel=347 ms
observed speedup=3.19x
maximum simultaneous device scans=4
```

The test requires at least 2.0x speedup and asserts that concurrency never exceeds
4. The production default is 4 and can be configured with
`LMIST_REPORT_CONCURRENCY` in the range 1-8. This does not claim that every real
network will achieve 3.19x; it proves the former sequential device bottleneck is
removed without unbounded fan-out.
