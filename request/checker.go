package request

import (
	"context"
	"time"
)

// FindApprovedRequest searches for a valid approved request for a specific user and profile.
// It queries the store for all requests by the requester, then filters for:
//   - Status == StatusApproved
//   - Profile matches the requested profile
//   - Request is not expired (ExpiresAt > now)
//   - Access window is still open (now < CreatedAt + Duration)
//
// Returns the first matching request if found, or nil if no valid approved request exists.
// Returns error only for store errors, not for "no approved request found".
func FindApprovedRequest(ctx context.Context, store Store, requester string, profile string) (*Request, error) {
	requests, err := store.ListByRequester(ctx, requester, MaxQueryLimit)
	if err != nil {
		return nil, err
	}

	for _, req := range requests {
		if req.Status == StatusApproved && req.Profile == profile && isRequestValid(req) {
			return req, nil
		}
	}

	return nil, nil
}

// isRequestValid checks if an approved request is still valid for credential issuance.
// A request is valid if:
//   - ExpiresAt > now (request hasn't expired)
//   - now < CreatedAt + Duration (access window is still open)
func isRequestValid(req *Request) bool {
	now := time.Now()

	// Check request hasn't expired
	if now.After(req.ExpiresAt) {
		return false
	}

	// Check access window is still open
	accessWindowEnd := req.CreatedAt.Add(req.Duration)
	if now.After(accessWindowEnd) {
		return false
	}

	return true
}
