# Progress and status reports

The project list and every binary view show progress reports.
Binary views refresh every two seconds while visible.
Live events also invalidate cached data when work changes.
The timestamp shows the last successful fetch. A request error remains visible beside cached reports.

Use **Download status report** to save the displayed reports as JSON.
The report includes its creation time, binary ID, run scope, phase counts, elapsed time, and estimates.

## Extraction

Extraction reports three phases:

1. Ghidra startup and analysis show elapsed time and the latest nonempty log line.
2. Function decompilation shows exported functions, total functions, and the function being processed.
3. Index import shows that the database transaction is still running.

The exporter writes a progress snapshot approximately once per second, between functions.
A slow function can delay that snapshot. The backend continues to refresh elapsed time during this period.
Failures preserve their error and elapsed time. Retrying extraction starts a new measurement.
Completed extraction reports preserve their final count and duration.

## Analysis

Each pass reports completed jobs, total jobs, active jobs, and jobs that need attention.
Reports use the active run when one is selected. Otherwise, they cover all runs.
The jobs table shows the duration of each job's latest attempt.
Retries reset that duration when the next attempt starts.
Older jobs without timing records show **No timing data** in that column.

Elapsed pass time includes pauses and retry delays.
Extraction elapsed time covers the entire extraction, while its estimate covers only function decompilation.

## Estimates

An unavailable estimate means the system lacks a useful measurement. It does not mean zero remaining time.

Decompilation estimates require at least three completed functions and two seconds in the measured phase.
The estimate extrapolates the average time per function. Different function sizes can change it substantially.

Analysis estimates use completed jobs from the last five minutes and their observed completion rate.
They require at least three samples and an active job.
Paused passes and passes with failed or uncertain jobs have no estimate.
Dependency barriers, provider latency, and later passes can change the remaining work.
These estimates describe currently queued work, not complete program recovery.

Ghidra startup, automatic analysis, index import, writeback, and recovery convergence have no numeric estimate.
Their work is not yet measured in predictable units.
The latest writeback and recovery records still expose their status, duration, and error.
Operation durations include time spent awaiting application of a preview.

## Current boundaries

Recovery remains a CLI workflow. Its process holds the data directory lock, so the web server cannot run beside it.
The recovery command prints status reports every five seconds.
Its stored iteration reports become visible when the server starts afterward.
The runtime collector prints observation counts, elapsed time, and remaining capture time every five seconds.
Its live capture progress is not streamed into the web interface.
