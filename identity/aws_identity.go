package identity

import (
	"errors"
	"fmt"
	"strings"
)

// IdentityType represents the type of AWS identity extracted from an ARN.
type IdentityType string

const (
	// IdentityTypeUser represents an IAM user.
	IdentityTypeUser IdentityType = "user"
	// IdentityTypeAssumedRole represents an assumed role (including SSO).
	IdentityTypeAssumedRole IdentityType = "assumed-role"
	// IdentityTypeFederatedUser represents a federated user.
	IdentityTypeFederatedUser IdentityType = "federated-user"
	// IdentityTypeRoot represents the AWS account root user.
	IdentityTypeRoot IdentityType = "root"
	// IdentityTypeUnknown represents an unrecognized identity type.
	IdentityTypeUnknown IdentityType = "unknown"
)

var (
	// ErrInvalidARN indicates the ARN format is invalid.
	ErrInvalidARN = errors.New("invalid ARN format")
	// ErrUnsupportedIdentityType indicates the ARN contains an unsupported identity type.
	ErrUnsupportedIdentityType = errors.New("unsupported identity type in ARN")
	// ErrEmptyARN indicates an empty ARN was provided.
	ErrEmptyARN = errors.New("ARN cannot be empty")
)

// validPartitions contains the set of valid AWS partitions.
var validPartitions = map[string]bool{
	"aws":        true, // Commercial
	"aws-cn":     true, // China
	"aws-us-gov": true, // GovCloud
}

// AWSIdentity contains the parsed identity information from an AWS ARN.
type AWSIdentity struct {
	// ARN is the full ARN string.
	ARN string
	// AccountID is the 12-digit AWS account ID.
	AccountID string
	// Type is the identity type (user, assumed-role, federated-user, root).
	Type IdentityType
	// Username is the sanitized username for policy matching.
	Username string
	// RawUsername is the unsanitized username for display purposes.
	RawUsername string
}

// ParseARN parses an AWS ARN and extracts identity information.
//
// Supported ARN formats:
//   - IAM User: arn:aws:iam::123456789012:user/alice
//   - IAM User with path: arn:aws:iam::123456789012:user/division/team/alice
//   - Assumed role: arn:aws:sts::123456789012:assumed-role/RoleName/session-name
//   - SSO assumed role: arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_.../email@company.com
//   - Federated user: arn:aws:sts::123456789012:federated-user/username
//   - Root: arn:aws:iam::123456789012:root
func ParseARN(arn string) (*AWSIdentity, error) {
	if arn == "" {
		return nil, ErrEmptyARN
	}

	// ARN format: arn:partition:service:region:account:resource
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return nil, fmt.Errorf("%w: expected 6 colon-separated parts, got %d", ErrInvalidARN, len(parts))
	}

	if parts[0] != "arn" {
		return nil, fmt.Errorf("%w: must start with 'arn:'", ErrInvalidARN)
	}

	partition := parts[1]
	if !validPartitions[partition] {
		return nil, fmt.Errorf("%w: invalid partition '%s'", ErrInvalidARN, partition)
	}

	service := parts[2]
	accountID := parts[4]
	resource := parts[5]

	// Validate account ID (must be 12 digits)
	if len(accountID) != 12 {
		return nil, fmt.Errorf("%w: account ID must be 12 digits, got '%s'", ErrInvalidARN, accountID)
	}

	identity := &AWSIdentity{
		ARN:       arn,
		AccountID: accountID,
	}

	// Parse based on service and resource type
	switch service {
	case "iam":
		return parseIAMResource(identity, resource)
	case "sts":
		return parseSTSResource(identity, resource)
	default:
		return nil, fmt.Errorf("%w: unsupported service '%s'", ErrUnsupportedIdentityType, service)
	}
}

// parseIAMResource parses IAM resource types (user, root).
func parseIAMResource(identity *AWSIdentity, resource string) (*AWSIdentity, error) {
	switch {
	case resource == "root":
		identity.Type = IdentityTypeRoot
		identity.RawUsername = "root"
		identity.Username = "root"
		return identity, nil

	case strings.HasPrefix(resource, "user/"):
		identity.Type = IdentityTypeUser
		// Extract username from path - could be user/alice or user/path/to/alice
		userPath := strings.TrimPrefix(resource, "user/")
		if userPath == "" {
			return nil, fmt.Errorf("%w: user path is empty", ErrInvalidARN)
		}
		// Get the last component of the path
		pathParts := strings.Split(userPath, "/")
		username := pathParts[len(pathParts)-1]
		if username == "" {
			return nil, fmt.Errorf("%w: username is empty", ErrInvalidARN)
		}
		identity.RawUsername = username
		sanitized, err := SanitizeUser(username)
		if err != nil {
			return nil, fmt.Errorf("failed to sanitize username: %w", err)
		}
		identity.Username = sanitized
		return identity, nil

	default:
		return nil, fmt.Errorf("%w: unknown IAM resource type in '%s'", ErrUnsupportedIdentityType, resource)
	}
}

// parseSTSResource parses STS resource types (assumed-role, federated-user).
func parseSTSResource(identity *AWSIdentity, resource string) (*AWSIdentity, error) {
	switch {
	case strings.HasPrefix(resource, "assumed-role/"):
		identity.Type = IdentityTypeAssumedRole
		// Format: assumed-role/role-name/session-name
		rolePath := strings.TrimPrefix(resource, "assumed-role/")
		parts := strings.SplitN(rolePath, "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%w: assumed-role must have format role-name/session-name", ErrInvalidARN)
		}
		sessionName := parts[1]
		if sessionName == "" {
			return nil, fmt.Errorf("%w: session name is empty", ErrInvalidARN)
		}
		identity.RawUsername = sessionName
		sanitized, err := SanitizeUser(sessionName)
		if err != nil {
			return nil, fmt.Errorf("failed to sanitize session name: %w", err)
		}
		identity.Username = sanitized
		return identity, nil

	case strings.HasPrefix(resource, "federated-user/"):
		identity.Type = IdentityTypeFederatedUser
		username := strings.TrimPrefix(resource, "federated-user/")
		if username == "" {
			return nil, fmt.Errorf("%w: federated user name is empty", ErrInvalidARN)
		}
		identity.RawUsername = username
		sanitized, err := SanitizeUser(username)
		if err != nil {
			return nil, fmt.Errorf("failed to sanitize federated user: %w", err)
		}
		identity.Username = sanitized
		return identity, nil

	default:
		return nil, fmt.Errorf("%w: unknown STS resource type in '%s'", ErrUnsupportedIdentityType, resource)
	}
}

// ExtractUsername extracts and sanitizes the username from an AWS ARN.
// This is a convenience function that wraps ParseARN and returns only the username.
func ExtractUsername(arn string) (string, error) {
	identity, err := ParseARN(arn)
	if err != nil {
		return "", err
	}
	return identity.Username, nil
}

// IsValid returns true if the identity type is a recognized type.
func (t IdentityType) IsValid() bool {
	switch t {
	case IdentityTypeUser, IdentityTypeAssumedRole, IdentityTypeFederatedUser, IdentityTypeRoot:
		return true
	default:
		return false
	}
}

// String returns the string representation of the identity type.
func (t IdentityType) String() string {
	return string(t)
}
