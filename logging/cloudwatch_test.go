package logging

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// MockCloudWatchAPI implements CloudWatchAPI for testing.
type MockCloudWatchAPI struct {
	mu     sync.Mutex
	calls  []PutLogEventsCall
	err    error
	tokens []string // Sequence tokens to return
}

// PutLogEventsCall records a single call to PutLogEvents.
type PutLogEventsCall struct {
	LogGroupName  string
	LogStreamName string
	Messages      []string
	Timestamps    []int64
	SequenceToken *string
}

func (m *MockCloudWatchAPI) PutLogEvents(ctx context.Context, params *cloudwatchlogs.PutLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.PutLogEventsOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	call := PutLogEventsCall{
		LogGroupName:  aws.ToString(params.LogGroupName),
		LogStreamName: aws.ToString(params.LogStreamName),
		SequenceToken: params.SequenceToken,
	}

	for _, event := range params.LogEvents {
		call.Messages = append(call.Messages, aws.ToString(event.Message))
		if event.Timestamp != nil {
			call.Timestamps = append(call.Timestamps, *event.Timestamp)
		}
	}

	m.calls = append(m.calls, call)

	if m.err != nil {
		return nil, m.err
	}

	// Return a sequence token if configured
	var nextToken *string
	if len(m.tokens) > len(m.calls)-1 {
		nextToken = aws.String(m.tokens[len(m.calls)-1])
	}

	return &cloudwatchlogs.PutLogEventsOutput{
		NextSequenceToken: nextToken,
	}, nil
}

func (m *MockCloudWatchAPI) GetCalls() []PutLogEventsCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestCloudWatchLogger_LogDecision_Unsigned(t *testing.T) {
	mock := &MockCloudWatchAPI{}
	config := &CloudWatchConfig{
		LogGroupName:  "/aws/lambda/sentinel-tvm",
		LogStreamName: "test-stream-123",
		SignConfig:    nil, // No signing
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	entry := DecisionLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Effect:    "allow",
		User:      "alice",
		Rule:      "default-allow",
		Profile:   "production",
	}

	logger.LogDecision(entry)

	calls := mock.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	call := calls[0]
	if call.LogGroupName != "/aws/lambda/sentinel-tvm" {
		t.Errorf("LogGroupName = %s, want /aws/lambda/sentinel-tvm", call.LogGroupName)
	}
	if call.LogStreamName != "test-stream-123" {
		t.Errorf("LogStreamName = %s, want test-stream-123", call.LogStreamName)
	}
	if len(call.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(call.Messages))
	}

	// Verify message is valid JSON
	var decoded DecisionLogEntry
	if err := json.Unmarshal([]byte(call.Messages[0]), &decoded); err != nil {
		t.Fatalf("message is not valid JSON: %v", err)
	}
	if decoded.Effect != "allow" {
		t.Errorf("decoded Effect = %s, want allow", decoded.Effect)
	}
	if decoded.User != "alice" {
		t.Errorf("decoded User = %s, want alice", decoded.User)
	}
}

func TestCloudWatchLogger_LogDecision_Signed(t *testing.T) {
	mock := &MockCloudWatchAPI{}
	signConfig := &SignatureConfig{
		KeyID:     "test-key-v1",
		SecretKey: make([]byte, 32), // 32 bytes for HMAC-SHA256
	}
	// Fill with test data
	for i := range signConfig.SecretKey {
		signConfig.SecretKey[i] = byte(i)
	}

	config := &CloudWatchConfig{
		LogGroupName:  "/aws/lambda/sentinel-tvm",
		LogStreamName: "test-stream-456",
		SignConfig:    signConfig,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	entry := DecisionLogEntry{
		Timestamp: "2026-01-26T12:00:00Z",
		Effect:    "deny",
		User:      "bob",
		Rule:      "restricted-access",
		Profile:   "production",
	}

	logger.LogDecision(entry)

	calls := mock.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	// Verify message is a SignedEntry
	var signed SignedEntry
	if err := json.Unmarshal([]byte(calls[0].Messages[0]), &signed); err != nil {
		t.Fatalf("message is not valid SignedEntry JSON: %v", err)
	}

	// Check signature fields are present
	if signed.Signature == "" {
		t.Error("expected signature to be set")
	}
	if signed.KeyID != "test-key-v1" {
		t.Errorf("KeyID = %s, want test-key-v1", signed.KeyID)
	}
	if signed.Timestamp == "" {
		t.Error("expected timestamp to be set")
	}

	// Verify the entry can be extracted
	var decoded DecisionLogEntry
	if err := signed.GetEntry(&decoded); err != nil {
		t.Fatalf("failed to extract entry: %v", err)
	}
	if decoded.Effect != "deny" {
		t.Errorf("decoded Effect = %s, want deny", decoded.Effect)
	}
}

func TestCloudWatchLogger_LogApproval(t *testing.T) {
	mock := &MockCloudWatchAPI{}
	config := &CloudWatchConfig{
		LogGroupName:  "/sentinel/approvals",
		LogStreamName: "approval-stream",
		SignConfig:    nil,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	entry := ApprovalLogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		RequestID: "req-1234567890abcdef",
		Event:     "request.approved",
		Requester: "alice",
		Profile:   "production",
		Status:    "approved",
		Actor:     "admin",
		Approver:  "admin",
		Duration:  3600,
	}

	logger.LogApproval(entry)

	calls := mock.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	// Verify it's valid JSON with expected fields
	var decoded ApprovalLogEntry
	if err := json.Unmarshal([]byte(calls[0].Messages[0]), &decoded); err != nil {
		t.Fatalf("message is not valid JSON: %v", err)
	}
	if decoded.RequestID != "req-1234567890abcdef" {
		t.Errorf("RequestID = %s, want req-1234567890abcdef", decoded.RequestID)
	}
}

func TestCloudWatchLogger_LogBreakGlass(t *testing.T) {
	mock := &MockCloudWatchAPI{}
	config := &CloudWatchConfig{
		LogGroupName:  "/sentinel/breakglass",
		LogStreamName: "emergency-stream",
		SignConfig:    nil,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	entry := BreakGlassLogEntry{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		RequestID:     "bg-1234567890abcdef",
		EventID:       "evt-1234567890abcdef",
		Event:         "breakglass.invoked",
		Invoker:       "oncall",
		Profile:       "production",
		ReasonCode:    "incident",
		Justification: "Production incident #12345",
		Status:        "active",
		Duration:      3600,
		ExpiresAt:     "2026-01-26T13:00:00Z",
	}

	logger.LogBreakGlass(entry)

	calls := mock.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	// Verify it's valid JSON with expected fields
	var decoded BreakGlassLogEntry
	if err := json.Unmarshal([]byte(calls[0].Messages[0]), &decoded); err != nil {
		t.Fatalf("message is not valid JSON: %v", err)
	}
	if decoded.RequestID != "bg-1234567890abcdef" {
		t.Errorf("RequestID = %s, want bg-1234567890abcdef", decoded.RequestID)
	}
	if decoded.Justification != "Production incident #12345" {
		t.Errorf("Justification = %s, want Production incident #12345", decoded.Justification)
	}
}

func TestCloudWatchLogger_SequenceTokenHandling(t *testing.T) {
	mock := &MockCloudWatchAPI{
		tokens: []string{"token-1", "token-2", "token-3"},
	}
	config := &CloudWatchConfig{
		LogGroupName:  "/test/logs",
		LogStreamName: "stream",
		SignConfig:    nil,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	// First call - no sequence token
	logger.LogDecision(DecisionLogEntry{Effect: "allow"})
	calls := mock.GetCalls()
	if calls[0].SequenceToken != nil {
		t.Error("first call should not have sequence token")
	}

	// Second call - should include token from first response
	logger.LogDecision(DecisionLogEntry{Effect: "deny"})
	calls = mock.GetCalls()
	if calls[1].SequenceToken == nil {
		t.Error("second call should have sequence token")
	}
	if *calls[1].SequenceToken != "token-1" {
		t.Errorf("sequence token = %s, want token-1", *calls[1].SequenceToken)
	}

	// Third call - should include token from second response
	logger.LogDecision(DecisionLogEntry{Effect: "allow"})
	calls = mock.GetCalls()
	if *calls[2].SequenceToken != "token-2" {
		t.Errorf("sequence token = %s, want token-2", *calls[2].SequenceToken)
	}
}

func TestCloudWatchLogger_ErrorHandling(t *testing.T) {
	mock := &MockCloudWatchAPI{
		err: &mockError{message: "ResourceNotFoundException: log group not found"},
	}
	config := &CloudWatchConfig{
		LogGroupName:  "/nonexistent/logs",
		LogStreamName: "stream",
		SignConfig:    nil,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	// Should not panic - errors are logged to stderr and swallowed
	logger.LogDecision(DecisionLogEntry{Effect: "allow"})

	calls := mock.GetCalls()
	if len(calls) != 1 {
		t.Errorf("expected 1 call even on error, got %d", len(calls))
	}
}

type mockError struct {
	message string
}

func (e *mockError) Error() string {
	return e.message
}

func TestCloudWatchLogger_SigningErrorFallback(t *testing.T) {
	mock := &MockCloudWatchAPI{}
	// Invalid signing config - key too short
	signConfig := &SignatureConfig{
		KeyID:     "invalid-key",
		SecretKey: make([]byte, 10), // Too short
	}

	config := &CloudWatchConfig{
		LogGroupName:  "/test/logs",
		LogStreamName: "stream",
		SignConfig:    signConfig,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	// Should fall back to unsigned entry
	logger.LogDecision(DecisionLogEntry{Effect: "allow"})

	calls := mock.GetCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	// Message should be unsigned (no signature field at top level)
	message := calls[0].Messages[0]
	if strings.Contains(message, `"signature"`) {
		t.Error("expected unsigned entry on signing error")
	}
}

func TestCloudWatchLogger_Timestamp(t *testing.T) {
	mock := &MockCloudWatchAPI{}
	config := &CloudWatchConfig{
		LogGroupName:  "/test/logs",
		LogStreamName: "stream",
		SignConfig:    nil,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	before := time.Now().UnixMilli()
	logger.LogDecision(DecisionLogEntry{Effect: "allow"})
	after := time.Now().UnixMilli()

	calls := mock.GetCalls()
	if len(calls[0].Timestamps) != 1 {
		t.Fatal("expected timestamp to be set")
	}

	ts := calls[0].Timestamps[0]
	if ts < before || ts > after {
		t.Errorf("timestamp %d not in range [%d, %d]", ts, before, after)
	}
}

func TestCloudWatchLogger_ConcurrentCalls(t *testing.T) {
	mock := &MockCloudWatchAPI{
		tokens: []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"},
	}
	config := &CloudWatchConfig{
		LogGroupName:  "/test/logs",
		LogStreamName: "stream",
		SignConfig:    nil,
	}

	logger := NewCloudWatchLoggerWithClient(mock, config)

	// Fire 10 concurrent log calls
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.LogDecision(DecisionLogEntry{Effect: "allow", Rule: string(rune('A' + n))})
		}(i)
	}
	wg.Wait()

	calls := mock.GetCalls()
	if len(calls) != 10 {
		t.Errorf("expected 10 calls, got %d", len(calls))
	}
}
