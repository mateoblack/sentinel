package testutil

import (
	"context"
	"sync"
	"time"

	"github.com/byteness/aws-vault/v7/breakglass"
	"github.com/byteness/aws-vault/v7/logging"
	"github.com/byteness/aws-vault/v7/notification"
	"github.com/byteness/aws-vault/v7/policy"
	"github.com/byteness/aws-vault/v7/request"
)

// ============================================================================
// MockRequestStore - implements request.Store interface
// ============================================================================

// MockRequestStore implements request.Store for testing.
// Supports configurable responses and in-memory storage for stateful tests.
type MockRequestStore struct {
	mu sync.Mutex

	// Configurable behavior functions
	CreateFunc          func(ctx context.Context, req *request.Request) error
	GetFunc             func(ctx context.Context, id string) (*request.Request, error)
	UpdateFunc          func(ctx context.Context, req *request.Request) error
	DeleteFunc          func(ctx context.Context, id string) error
	ListByRequesterFunc func(ctx context.Context, requester string, limit int) ([]*request.Request, error)
	ListByStatusFunc    func(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error)
	ListByProfileFunc   func(ctx context.Context, profile string, limit int) ([]*request.Request, error)

	// Error injection (used if behavior function is nil)
	CreateErr          error
	GetErr             error
	UpdateErr          error
	DeleteErr          error
	ListByRequesterErr error
	ListByStatusErr    error
	ListByProfileErr   error

	// In-memory storage for stateful tests
	Requests map[string]*request.Request

	// Call tracking
	CreateCalls          []*request.Request
	GetCalls             []string
	UpdateCalls          []*request.Request
	DeleteCalls          []string
	ListByRequesterCalls []ListByRequesterCall
	ListByStatusCalls    []ListByStatusCall
	ListByProfileCalls   []ListByProfileCall
}

// ListByRequesterCall tracks parameters for ListByRequester calls.
type ListByRequesterCall struct {
	Requester string
	Limit     int
}

// ListByStatusCall tracks parameters for ListByStatus calls.
type ListByStatusCall struct {
	Status request.RequestStatus
	Limit  int
}

// ListByProfileCall tracks parameters for ListByProfile calls.
type ListByProfileCall struct {
	Profile string
	Limit   int
}

// NewMockRequestStore creates a new MockRequestStore with initialized maps.
func NewMockRequestStore() *MockRequestStore {
	return &MockRequestStore{
		Requests: make(map[string]*request.Request),
	}
}

// Create stores a new request.
func (m *MockRequestStore) Create(ctx context.Context, req *request.Request) error {
	m.mu.Lock()
	m.CreateCalls = append(m.CreateCalls, req)
	m.mu.Unlock()

	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, req)
	}
	if m.CreateErr != nil {
		return m.CreateErr
	}
	// Default: store in memory
	m.mu.Lock()
	if m.Requests == nil {
		m.Requests = make(map[string]*request.Request)
	}
	m.Requests[req.ID] = req
	m.mu.Unlock()
	return nil
}

// Get retrieves a request by ID.
func (m *MockRequestStore) Get(ctx context.Context, id string) (*request.Request, error) {
	m.mu.Lock()
	m.GetCalls = append(m.GetCalls, id)
	m.mu.Unlock()

	if m.GetFunc != nil {
		return m.GetFunc(ctx, id)
	}
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if req, ok := m.Requests[id]; ok {
		return req, nil
	}
	return nil, request.ErrRequestNotFound
}

// Update modifies an existing request.
func (m *MockRequestStore) Update(ctx context.Context, req *request.Request) error {
	m.mu.Lock()
	m.UpdateCalls = append(m.UpdateCalls, req)
	m.mu.Unlock()

	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, req)
	}
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Requests == nil {
		return request.ErrRequestNotFound
	}
	if _, ok := m.Requests[req.ID]; !ok {
		return request.ErrRequestNotFound
	}
	m.Requests[req.ID] = req
	return nil
}

// Delete removes a request by ID.
func (m *MockRequestStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	m.DeleteCalls = append(m.DeleteCalls, id)
	m.mu.Unlock()

	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, id)
	}
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Requests, id)
	return nil
}

// ListByRequester returns requests from a specific user.
func (m *MockRequestStore) ListByRequester(ctx context.Context, requester string, limit int) ([]*request.Request, error) {
	m.mu.Lock()
	m.ListByRequesterCalls = append(m.ListByRequesterCalls, ListByRequesterCall{Requester: requester, Limit: limit})
	m.mu.Unlock()

	if m.ListByRequesterFunc != nil {
		return m.ListByRequesterFunc(ctx, requester, limit)
	}
	if m.ListByRequesterErr != nil {
		return nil, m.ListByRequesterErr
	}
	return nil, nil
}

// ListByStatus returns requests with a specific status.
func (m *MockRequestStore) ListByStatus(ctx context.Context, status request.RequestStatus, limit int) ([]*request.Request, error) {
	m.mu.Lock()
	m.ListByStatusCalls = append(m.ListByStatusCalls, ListByStatusCall{Status: status, Limit: limit})
	m.mu.Unlock()

	if m.ListByStatusFunc != nil {
		return m.ListByStatusFunc(ctx, status, limit)
	}
	if m.ListByStatusErr != nil {
		return nil, m.ListByStatusErr
	}
	return nil, nil
}

// ListByProfile returns requests for a specific profile.
func (m *MockRequestStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*request.Request, error) {
	m.mu.Lock()
	m.ListByProfileCalls = append(m.ListByProfileCalls, ListByProfileCall{Profile: profile, Limit: limit})
	m.mu.Unlock()

	if m.ListByProfileFunc != nil {
		return m.ListByProfileFunc(ctx, profile, limit)
	}
	if m.ListByProfileErr != nil {
		return nil, m.ListByProfileErr
	}
	return nil, nil
}

// Reset clears all call tracking and stored data.
func (m *MockRequestStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CreateCalls = nil
	m.GetCalls = nil
	m.UpdateCalls = nil
	m.DeleteCalls = nil
	m.ListByRequesterCalls = nil
	m.ListByStatusCalls = nil
	m.ListByProfileCalls = nil
	m.Requests = make(map[string]*request.Request)
}

// ============================================================================
// MockBreakGlassStore - implements breakglass.Store interface
// ============================================================================

// MockBreakGlassStore implements breakglass.Store for testing.
// Supports configurable responses and in-memory storage for stateful tests.
type MockBreakGlassStore struct {
	mu sync.Mutex

	// Configurable behavior functions
	CreateFunc                        func(ctx context.Context, event *breakglass.BreakGlassEvent) error
	GetFunc                           func(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error)
	UpdateFunc                        func(ctx context.Context, event *breakglass.BreakGlassEvent) error
	DeleteFunc                        func(ctx context.Context, id string) error
	ListByInvokerFunc                 func(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error)
	ListByStatusFunc                  func(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error)
	ListByProfileFunc                 func(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error)
	FindActiveByInvokerAndProfileFunc func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error)
	CountByInvokerSinceFunc           func(ctx context.Context, invoker string, since time.Time) (int, error)
	CountByProfileSinceFunc           func(ctx context.Context, profile string, since time.Time) (int, error)
	GetLastByInvokerAndProfileFunc    func(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error)

	// Error injection (used if behavior function is nil)
	CreateErr                        error
	GetErr                           error
	UpdateErr                        error
	DeleteErr                        error
	ListByInvokerErr                 error
	ListByStatusErr                  error
	ListByProfileErr                 error
	FindActiveByInvokerAndProfileErr error
	CountByInvokerSinceErr           error
	CountByProfileSinceErr           error
	GetLastByInvokerAndProfileErr    error

	// In-memory storage for stateful tests
	Events map[string]*breakglass.BreakGlassEvent

	// Call tracking
	CreateCalls                        []*breakglass.BreakGlassEvent
	GetCalls                           []string
	UpdateCalls                        []*breakglass.BreakGlassEvent
	DeleteCalls                        []string
	ListByInvokerCalls                 []BreakGlassListByInvokerCall
	ListByStatusCalls                  []BreakGlassListByStatusCall
	ListByProfileCalls                 []BreakGlassListByProfileCall
	FindActiveByInvokerAndProfileCalls []FindActiveCall
	CountByInvokerSinceCalls           []CountByInvokerCall
	CountByProfileSinceCalls           []CountByProfileCall
	GetLastByInvokerAndProfileCalls    []GetLastCall
}

// BreakGlassListByInvokerCall tracks parameters for ListByInvoker calls.
type BreakGlassListByInvokerCall struct {
	Invoker string
	Limit   int
}

// BreakGlassListByStatusCall tracks parameters for ListByStatus calls.
type BreakGlassListByStatusCall struct {
	Status breakglass.BreakGlassStatus
	Limit  int
}

// BreakGlassListByProfileCall tracks parameters for ListByProfile calls.
type BreakGlassListByProfileCall struct {
	Profile string
	Limit   int
}

// FindActiveCall tracks parameters for FindActiveByInvokerAndProfile calls.
type FindActiveCall struct {
	Invoker string
	Profile string
}

// CountByInvokerCall tracks parameters for CountByInvokerSince calls.
type CountByInvokerCall struct {
	Invoker string
	Since   time.Time
}

// CountByProfileCall tracks parameters for CountByProfileSince calls.
type CountByProfileCall struct {
	Profile string
	Since   time.Time
}

// GetLastCall tracks parameters for GetLastByInvokerAndProfile calls.
type GetLastCall struct {
	Invoker string
	Profile string
}

// NewMockBreakGlassStore creates a new MockBreakGlassStore with initialized maps.
func NewMockBreakGlassStore() *MockBreakGlassStore {
	return &MockBreakGlassStore{
		Events: make(map[string]*breakglass.BreakGlassEvent),
	}
}

// Create stores a new break-glass event.
func (m *MockBreakGlassStore) Create(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	m.mu.Lock()
	m.CreateCalls = append(m.CreateCalls, event)
	m.mu.Unlock()

	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, event)
	}
	if m.CreateErr != nil {
		return m.CreateErr
	}
	m.mu.Lock()
	if m.Events == nil {
		m.Events = make(map[string]*breakglass.BreakGlassEvent)
	}
	m.Events[event.ID] = event
	m.mu.Unlock()
	return nil
}

// Get retrieves a break-glass event by ID.
func (m *MockBreakGlassStore) Get(ctx context.Context, id string) (*breakglass.BreakGlassEvent, error) {
	m.mu.Lock()
	m.GetCalls = append(m.GetCalls, id)
	m.mu.Unlock()

	if m.GetFunc != nil {
		return m.GetFunc(ctx, id)
	}
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if event, ok := m.Events[id]; ok {
		return event, nil
	}
	return nil, breakglass.ErrEventNotFound
}

// Update modifies an existing event.
func (m *MockBreakGlassStore) Update(ctx context.Context, event *breakglass.BreakGlassEvent) error {
	m.mu.Lock()
	m.UpdateCalls = append(m.UpdateCalls, event)
	m.mu.Unlock()

	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, event)
	}
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Events == nil {
		return breakglass.ErrEventNotFound
	}
	if _, ok := m.Events[event.ID]; !ok {
		return breakglass.ErrEventNotFound
	}
	m.Events[event.ID] = event
	return nil
}

// Delete removes an event by ID.
func (m *MockBreakGlassStore) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	m.DeleteCalls = append(m.DeleteCalls, id)
	m.mu.Unlock()

	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, id)
	}
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Events, id)
	return nil
}

// ListByInvoker returns events from a specific user.
func (m *MockBreakGlassStore) ListByInvoker(ctx context.Context, invoker string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	m.mu.Lock()
	m.ListByInvokerCalls = append(m.ListByInvokerCalls, BreakGlassListByInvokerCall{Invoker: invoker, Limit: limit})
	m.mu.Unlock()

	if m.ListByInvokerFunc != nil {
		return m.ListByInvokerFunc(ctx, invoker, limit)
	}
	if m.ListByInvokerErr != nil {
		return nil, m.ListByInvokerErr
	}
	return nil, nil
}

// ListByStatus returns events with a specific status.
func (m *MockBreakGlassStore) ListByStatus(ctx context.Context, status breakglass.BreakGlassStatus, limit int) ([]*breakglass.BreakGlassEvent, error) {
	m.mu.Lock()
	m.ListByStatusCalls = append(m.ListByStatusCalls, BreakGlassListByStatusCall{Status: status, Limit: limit})
	m.mu.Unlock()

	if m.ListByStatusFunc != nil {
		return m.ListByStatusFunc(ctx, status, limit)
	}
	if m.ListByStatusErr != nil {
		return nil, m.ListByStatusErr
	}
	return nil, nil
}

// ListByProfile returns events for a specific profile.
func (m *MockBreakGlassStore) ListByProfile(ctx context.Context, profile string, limit int) ([]*breakglass.BreakGlassEvent, error) {
	m.mu.Lock()
	m.ListByProfileCalls = append(m.ListByProfileCalls, BreakGlassListByProfileCall{Profile: profile, Limit: limit})
	m.mu.Unlock()

	if m.ListByProfileFunc != nil {
		return m.ListByProfileFunc(ctx, profile, limit)
	}
	if m.ListByProfileErr != nil {
		return nil, m.ListByProfileErr
	}
	return nil, nil
}

// FindActiveByInvokerAndProfile checks for active break-glass access.
func (m *MockBreakGlassStore) FindActiveByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	m.mu.Lock()
	m.FindActiveByInvokerAndProfileCalls = append(m.FindActiveByInvokerAndProfileCalls, FindActiveCall{Invoker: invoker, Profile: profile})
	m.mu.Unlock()

	if m.FindActiveByInvokerAndProfileFunc != nil {
		return m.FindActiveByInvokerAndProfileFunc(ctx, invoker, profile)
	}
	if m.FindActiveByInvokerAndProfileErr != nil {
		return nil, m.FindActiveByInvokerAndProfileErr
	}
	return nil, nil
}

// CountByInvokerSince counts events from a user since the given time.
func (m *MockBreakGlassStore) CountByInvokerSince(ctx context.Context, invoker string, since time.Time) (int, error) {
	m.mu.Lock()
	m.CountByInvokerSinceCalls = append(m.CountByInvokerSinceCalls, CountByInvokerCall{Invoker: invoker, Since: since})
	m.mu.Unlock()

	if m.CountByInvokerSinceFunc != nil {
		return m.CountByInvokerSinceFunc(ctx, invoker, since)
	}
	if m.CountByInvokerSinceErr != nil {
		return 0, m.CountByInvokerSinceErr
	}
	return 0, nil
}

// CountByProfileSince counts events for a profile since the given time.
func (m *MockBreakGlassStore) CountByProfileSince(ctx context.Context, profile string, since time.Time) (int, error) {
	m.mu.Lock()
	m.CountByProfileSinceCalls = append(m.CountByProfileSinceCalls, CountByProfileCall{Profile: profile, Since: since})
	m.mu.Unlock()

	if m.CountByProfileSinceFunc != nil {
		return m.CountByProfileSinceFunc(ctx, profile, since)
	}
	if m.CountByProfileSinceErr != nil {
		return 0, m.CountByProfileSinceErr
	}
	return 0, nil
}

// GetLastByInvokerAndProfile returns the most recent event for a user+profile.
func (m *MockBreakGlassStore) GetLastByInvokerAndProfile(ctx context.Context, invoker, profile string) (*breakglass.BreakGlassEvent, error) {
	m.mu.Lock()
	m.GetLastByInvokerAndProfileCalls = append(m.GetLastByInvokerAndProfileCalls, GetLastCall{Invoker: invoker, Profile: profile})
	m.mu.Unlock()

	if m.GetLastByInvokerAndProfileFunc != nil {
		return m.GetLastByInvokerAndProfileFunc(ctx, invoker, profile)
	}
	if m.GetLastByInvokerAndProfileErr != nil {
		return nil, m.GetLastByInvokerAndProfileErr
	}
	return nil, nil
}

// Reset clears all call tracking and stored data.
func (m *MockBreakGlassStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CreateCalls = nil
	m.GetCalls = nil
	m.UpdateCalls = nil
	m.DeleteCalls = nil
	m.ListByInvokerCalls = nil
	m.ListByStatusCalls = nil
	m.ListByProfileCalls = nil
	m.FindActiveByInvokerAndProfileCalls = nil
	m.CountByInvokerSinceCalls = nil
	m.CountByProfileSinceCalls = nil
	m.GetLastByInvokerAndProfileCalls = nil
	m.Events = make(map[string]*breakglass.BreakGlassEvent)
}

// ============================================================================
// MockPolicyLoader - policy loading
// ============================================================================

// MockPolicyLoader provides configurable policy responses for testing.
type MockPolicyLoader struct {
	mu sync.Mutex

	// Configurable behavior functions
	LoadFunc func(ctx context.Context, parameterName string) (*policy.Policy, error)

	// Predefined responses per parameter name
	Policies map[string]*policy.Policy

	// Error injection
	LoadErr error

	// Call tracking
	LoadCalls []string
}

// NewMockPolicyLoader creates a new MockPolicyLoader with initialized maps.
func NewMockPolicyLoader() *MockPolicyLoader {
	return &MockPolicyLoader{
		Policies: make(map[string]*policy.Policy),
	}
}

// Load fetches a policy by parameter name.
func (m *MockPolicyLoader) Load(ctx context.Context, parameterName string) (*policy.Policy, error) {
	m.mu.Lock()
	m.LoadCalls = append(m.LoadCalls, parameterName)
	m.mu.Unlock()

	if m.LoadFunc != nil {
		return m.LoadFunc(ctx, parameterName)
	}
	if m.LoadErr != nil {
		return nil, m.LoadErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.Policies[parameterName]; ok {
		return p, nil
	}
	return nil, policy.ErrPolicyNotFound
}

// Reset clears all call tracking and predefined policies.
func (m *MockPolicyLoader) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.LoadCalls = nil
	m.Policies = make(map[string]*policy.Policy)
}

// ============================================================================
// MockNotifier - notification.Notifier interface
// ============================================================================

// MockNotifier implements notification.Notifier for testing.
// Tracks all notification calls for assertions.
type MockNotifier struct {
	mu sync.Mutex

	// Configurable behavior function
	NotifyFunc func(ctx context.Context, event *notification.Event) error

	// Error injection
	NotifyErr error

	// Call tracking
	NotifyCalls []*notification.Event
}

// NewMockNotifier creates a new MockNotifier.
func NewMockNotifier() *MockNotifier {
	return &MockNotifier{}
}

// Notify sends a notification.
func (m *MockNotifier) Notify(ctx context.Context, event *notification.Event) error {
	m.mu.Lock()
	m.NotifyCalls = append(m.NotifyCalls, event)
	m.mu.Unlock()

	if m.NotifyFunc != nil {
		return m.NotifyFunc(ctx, event)
	}
	if m.NotifyErr != nil {
		return m.NotifyErr
	}
	return nil
}

// Reset clears all call tracking.
func (m *MockNotifier) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NotifyCalls = nil
}

// NotifyCallCount returns the number of Notify calls made.
func (m *MockNotifier) NotifyCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.NotifyCalls)
}

// LastNotification returns the last notification event, or nil if none.
func (m *MockNotifier) LastNotification() *notification.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.NotifyCalls) == 0 {
		return nil
	}
	return m.NotifyCalls[len(m.NotifyCalls)-1]
}

// ============================================================================
// MockLogger - logging.Logger interface
// ============================================================================

// MockLogger implements logging.Logger for testing.
// Captures all log entries for assertions.
type MockLogger struct {
	mu sync.Mutex

	// Captured log entries
	DecisionEntries   []logging.DecisionLogEntry
	ApprovalEntries   []logging.ApprovalLogEntry
	BreakGlassEntries []logging.BreakGlassLogEntry
}

// NewMockLogger creates a new MockLogger.
func NewMockLogger() *MockLogger {
	return &MockLogger{}
}

// LogDecision logs a decision entry.
func (m *MockLogger) LogDecision(entry logging.DecisionLogEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DecisionEntries = append(m.DecisionEntries, entry)
}

// LogApproval logs an approval workflow event.
func (m *MockLogger) LogApproval(entry logging.ApprovalLogEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ApprovalEntries = append(m.ApprovalEntries, entry)
}

// LogBreakGlass logs a break-glass emergency access event.
func (m *MockLogger) LogBreakGlass(entry logging.BreakGlassLogEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.BreakGlassEntries = append(m.BreakGlassEntries, entry)
}

// Reset clears all captured log entries.
func (m *MockLogger) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DecisionEntries = nil
	m.ApprovalEntries = nil
	m.BreakGlassEntries = nil
}

// DecisionCount returns the number of decision log entries.
func (m *MockLogger) DecisionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.DecisionEntries)
}

// ApprovalCount returns the number of approval log entries.
func (m *MockLogger) ApprovalCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ApprovalEntries)
}

// BreakGlassCount returns the number of break-glass log entries.
func (m *MockLogger) BreakGlassCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.BreakGlassEntries)
}

// LastDecision returns the last decision log entry, or empty if none.
func (m *MockLogger) LastDecision() logging.DecisionLogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.DecisionEntries) == 0 {
		return logging.DecisionLogEntry{}
	}
	return m.DecisionEntries[len(m.DecisionEntries)-1]
}

// LastApproval returns the last approval log entry, or empty if none.
func (m *MockLogger) LastApproval() logging.ApprovalLogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.ApprovalEntries) == 0 {
		return logging.ApprovalLogEntry{}
	}
	return m.ApprovalEntries[len(m.ApprovalEntries)-1]
}

// LastBreakGlass returns the last break-glass log entry, or empty if none.
func (m *MockLogger) LastBreakGlass() logging.BreakGlassLogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.BreakGlassEntries) == 0 {
		return logging.BreakGlassLogEntry{}
	}
	return m.BreakGlassEntries[len(m.BreakGlassEntries)-1]
}

// ============================================================================
// MockBreakGlassNotifier - notification.BreakGlassNotifier interface
// ============================================================================

// MockBreakGlassNotifier implements notification.BreakGlassNotifier for testing.
// Tracks all break-glass notification calls for assertions.
type MockBreakGlassNotifier struct {
	mu sync.Mutex

	// Configurable behavior function
	NotifyBreakGlassFunc func(ctx context.Context, event *notification.BreakGlassEvent) error

	// Error injection
	NotifyBreakGlassErr error

	// Call tracking
	NotifyBreakGlassCalls []*notification.BreakGlassEvent
}

// NewMockBreakGlassNotifier creates a new MockBreakGlassNotifier.
func NewMockBreakGlassNotifier() *MockBreakGlassNotifier {
	return &MockBreakGlassNotifier{}
}

// NotifyBreakGlass sends a break-glass notification.
func (m *MockBreakGlassNotifier) NotifyBreakGlass(ctx context.Context, event *notification.BreakGlassEvent) error {
	m.mu.Lock()
	m.NotifyBreakGlassCalls = append(m.NotifyBreakGlassCalls, event)
	m.mu.Unlock()

	if m.NotifyBreakGlassFunc != nil {
		return m.NotifyBreakGlassFunc(ctx, event)
	}
	if m.NotifyBreakGlassErr != nil {
		return m.NotifyBreakGlassErr
	}
	return nil
}

// Reset clears all call tracking.
func (m *MockBreakGlassNotifier) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.NotifyBreakGlassCalls = nil
}

// NotifyCount returns the number of NotifyBreakGlass calls made.
func (m *MockBreakGlassNotifier) NotifyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.NotifyBreakGlassCalls)
}

// LastNotification returns the last break-glass event, or nil if none.
func (m *MockBreakGlassNotifier) LastNotification() *notification.BreakGlassEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.NotifyBreakGlassCalls) == 0 {
		return nil
	}
	return m.NotifyBreakGlassCalls[len(m.NotifyBreakGlassCalls)-1]
}
