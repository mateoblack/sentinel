//go:build loadtest

// Package testutil provides reusable test utilities, mock implementations,
// and helper functions for testing Sentinel components.
//
// This file provides load testing infrastructure for sustained load simulation.
package testutil

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// LoadTestConfig configures a load test run.
type LoadTestConfig struct {
	// RequestsPerSecond is the target request rate.
	RequestsPerSecond int

	// Duration is how long to run the test.
	Duration time.Duration

	// Workers is the number of concurrent worker goroutines.
	Workers int

	// Timeout is the per-request timeout.
	Timeout time.Duration
}

// LoadTestResult contains the results of a load test run.
type LoadTestResult struct {
	// TotalRequests is the number of requests attempted.
	TotalRequests int

	// SuccessCount is the number of successful requests.
	SuccessCount int

	// ErrorCount is the number of failed requests.
	ErrorCount int

	// LatencyP50 is the median latency.
	LatencyP50 time.Duration

	// LatencyP95 is the 95th percentile latency.
	LatencyP95 time.Duration

	// LatencyP99 is the 99th percentile latency.
	LatencyP99 time.Duration

	// Throughput is the actual requests per second achieved.
	Throughput float64

	// Duration is the actual test duration.
	Duration time.Duration

	// Errors contains unique error messages and their counts.
	Errors map[string]int
}

// SuccessRate returns the percentage of successful requests.
func (r LoadTestResult) SuccessRate() float64 {
	if r.TotalRequests == 0 {
		return 100.0
	}
	return float64(r.SuccessCount) / float64(r.TotalRequests) * 100.0
}

// workerResult holds results from a single worker goroutine.
type workerResult struct {
	latencies []time.Duration
	errors    []error
}

// RunLoadTest runs a load test with the given configuration.
// The requestFn is called for each request and should return nil on success.
// The test runs until Duration elapses or context is cancelled.
func RunLoadTest(ctx context.Context, config LoadTestConfig, requestFn func(ctx context.Context) error) LoadTestResult {
	// Create rate limiter
	limiter := rate.NewLimiter(rate.Limit(config.RequestsPerSecond), config.RequestsPerSecond)

	// Create context with deadline
	testCtx, cancel := context.WithTimeout(ctx, config.Duration)
	defer cancel()

	// Atomic counter for request generation
	var requestCount atomic.Int64

	// Channel for signaling test completion
	done := make(chan struct{})

	// Per-worker results (no channels needed)
	workerResults := make([]workerResult, config.Workers)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < config.Workers; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			// Pre-allocate per-worker slice for results
			localLatencies := make([]time.Duration, 0, config.RequestsPerSecond*int(config.Duration.Seconds())/config.Workers+100)
			localErrors := make([]error, 0, 100) // Errors should be rare

			for {
				select {
				case <-testCtx.Done():
					workerResults[workerID] = workerResult{latencies: localLatencies, errors: localErrors}
					return
				case <-done:
					workerResults[workerID] = workerResult{latencies: localLatencies, errors: localErrors}
					return
				default:
					// Try to claim work
					if requestCount.Add(1) > int64(config.RequestsPerSecond)*int64(config.Duration.Seconds()) {
						// All work claimed, wait for context
						requestCount.Add(-1) // Return the claim
						select {
						case <-testCtx.Done():
						case <-done:
						}
						workerResults[workerID] = workerResult{latencies: localLatencies, errors: localErrors}
						return
					}

					// Wait for rate limiter
					if err := limiter.Wait(testCtx); err != nil {
						workerResults[workerID] = workerResult{latencies: localLatencies, errors: localErrors}
						return
					}

					// Execute request
					start := time.Now()
					err := requestFn(testCtx)
					elapsed := time.Since(start)

					if err != nil {
						localErrors = append(localErrors, err)
					} else {
						localLatencies = append(localLatencies, elapsed)
					}
				}
			}
		}()
	}

	// Record start time
	startTime := time.Now()

	// Wait for context to complete (duration elapsed)
	<-testCtx.Done()

	// Signal workers to stop
	close(done)

	// Wait for all workers to finish
	wg.Wait()

	actualDuration := time.Since(startTime)

	// Aggregate results from all workers
	var allLatencies []time.Duration
	errorCounts := make(map[string]int)
	totalErrors := 0

	for _, wr := range workerResults {
		allLatencies = append(allLatencies, wr.latencies...)
		for _, err := range wr.errors {
			errorCounts[err.Error()]++
			totalErrors++
		}
	}

	// Build result
	result := LoadTestResult{
		TotalRequests: len(allLatencies) + totalErrors,
		SuccessCount:  len(allLatencies),
		ErrorCount:    totalErrors,
		Duration:      actualDuration,
		Errors:        errorCounts,
	}

	if len(allLatencies) > 0 {
		result.LatencyP50 = calculatePercentile(allLatencies, 50)
		result.LatencyP95 = calculatePercentile(allLatencies, 95)
		result.LatencyP99 = calculatePercentile(allLatencies, 99)
	}

	if actualDuration > 0 {
		result.Throughput = float64(result.TotalRequests) / actualDuration.Seconds()
	}

	return result
}

// calculatePercentile calculates the pth percentile of the given samples.
// p should be in the range [0, 100].
func calculatePercentile(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}

	// Sort samples
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	// Calculate index
	index := (p / 100.0) * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1
	if upper >= len(sorted) {
		upper = len(sorted) - 1
	}

	// Linear interpolation
	weight := index - float64(lower)
	return time.Duration(float64(sorted[lower])*(1-weight) + float64(sorted[upper])*weight)
}

// FormatLoadTestResult formats a LoadTestResult as a human-readable string.
func FormatLoadTestResult(result LoadTestResult) string {
	s := fmt.Sprintf(`Load Test Results:
  Duration:     %v
  Requests:     %d total, %d success, %d errors (%.1f%% success rate)
  Throughput:   %.1f req/sec
  Latency:
    P50:        %v
    P95:        %v
    P99:        %v`,
		result.Duration.Round(time.Millisecond),
		result.TotalRequests,
		result.SuccessCount,
		result.ErrorCount,
		result.SuccessRate(),
		result.Throughput,
		result.LatencyP50.Round(time.Microsecond),
		result.LatencyP95.Round(time.Microsecond),
		result.LatencyP99.Round(time.Microsecond),
	)

	if len(result.Errors) > 0 {
		s += "\n  Errors:"
		for msg, count := range result.Errors {
			s += fmt.Sprintf("\n    %d x %s", count, msg)
		}
	}

	return s
}
