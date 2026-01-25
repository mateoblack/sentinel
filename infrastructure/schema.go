// Package infrastructure provides types and utilities for provisioning
// Sentinel's infrastructure resources such as DynamoDB tables.
package infrastructure

import (
	"errors"
	"fmt"
)

// KeyType represents a DynamoDB attribute type for keys.
type KeyType string

const (
	// KeyTypeString represents the DynamoDB String type.
	KeyTypeString KeyType = "S"
	// KeyTypeNumber represents the DynamoDB Number type.
	KeyTypeNumber KeyType = "N"
	// KeyTypeBinary represents the DynamoDB Binary type.
	KeyTypeBinary KeyType = "B"
)

// IsValid returns true if the KeyType is a valid DynamoDB key type.
func (kt KeyType) IsValid() bool {
	return kt == KeyTypeString || kt == KeyTypeNumber || kt == KeyTypeBinary
}

// String returns the string representation of the KeyType.
func (kt KeyType) String() string {
	return string(kt)
}

// BillingMode represents DynamoDB table billing mode.
type BillingMode string

const (
	// BillingModePayPerRequest is on-demand billing mode.
	BillingModePayPerRequest BillingMode = "PAY_PER_REQUEST"
	// BillingModeProvisioned is provisioned capacity billing mode.
	BillingModeProvisioned BillingMode = "PROVISIONED"
)

// EncryptionType represents the encryption type for DynamoDB tables.
type EncryptionType string

const (
	// EncryptionDefault uses AWS owned encryption (default for DynamoDB).
	EncryptionDefault EncryptionType = "DEFAULT"
	// EncryptionKMS uses AWS managed KMS key for encryption.
	EncryptionKMS EncryptionType = "KMS"
	// EncryptionCustomerKey uses a customer-provided CMK ARN.
	EncryptionCustomerKey EncryptionType = "CUSTOMER_KEY"
)

// IsValid returns true if the EncryptionType is a valid encryption type.
func (et EncryptionType) IsValid() bool {
	return et == EncryptionDefault || et == EncryptionKMS || et == EncryptionCustomerKey
}

// String returns the string representation of the EncryptionType.
func (et EncryptionType) String() string {
	return string(et)
}

// EncryptionConfig represents the encryption configuration for a DynamoDB table.
type EncryptionConfig struct {
	// Type is the encryption type (required).
	Type EncryptionType
	// KMSKeyARN is the ARN of the customer-provided CMK (only used when Type is EncryptionCustomerKey).
	KMSKeyARN string
}

// Validate checks if the EncryptionConfig has valid values.
func (ec EncryptionConfig) Validate() error {
	if !ec.Type.IsValid() {
		return fmt.Errorf("invalid encryption type %q: must be DEFAULT, KMS, or CUSTOMER_KEY", ec.Type)
	}
	switch ec.Type {
	case EncryptionDefault, EncryptionKMS:
		// AWS managed encryption - KMSKeyARN must be empty
		if ec.KMSKeyARN != "" {
			return fmt.Errorf("KMSKeyARN must be empty for encryption type %s", ec.Type)
		}
	case EncryptionCustomerKey:
		// Customer-provided CMK - KMSKeyARN is required
		if ec.KMSKeyARN == "" {
			return errors.New("KMSKeyARN is required for encryption type CUSTOMER_KEY")
		}
		// Basic ARN format validation
		if !isValidKMSKeyARN(ec.KMSKeyARN) {
			return fmt.Errorf("invalid KMSKeyARN format: %s", ec.KMSKeyARN)
		}
	}
	return nil
}

// isValidKMSKeyARN performs basic validation of a KMS key ARN format.
func isValidKMSKeyARN(arn string) bool {
	// KMS key ARNs follow the pattern: arn:aws:kms:<region>:<account>:key/<key-id>
	// or arn:aws:kms:<region>:<account>:alias/<alias-name>
	return len(arn) > 20 && (contains(arn, ":key/") || contains(arn, ":alias/"))
}

// contains checks if s contains substr (helper to avoid importing strings package).
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// DefaultEncryptionKMS returns an EncryptionConfig with AWS managed KMS encryption.
// This is the recommended default for new tables - provides encryption at rest
// without the complexity of managing custom CMKs.
func DefaultEncryptionKMS() *EncryptionConfig {
	return &EncryptionConfig{Type: EncryptionKMS}
}

// IsValid returns true if the BillingMode is a valid DynamoDB billing mode.
func (bm BillingMode) IsValid() bool {
	return bm == BillingModePayPerRequest || bm == BillingModeProvisioned
}

// String returns the string representation of the BillingMode.
func (bm BillingMode) String() string {
	return string(bm)
}

// ProjectionType represents a GSI projection type.
type ProjectionType string

const (
	// ProjectionAll projects all attributes.
	ProjectionAll ProjectionType = "ALL"
	// ProjectionKeysOnly projects only key attributes.
	ProjectionKeysOnly ProjectionType = "KEYS_ONLY"
	// ProjectionInclude projects specified attributes plus keys.
	ProjectionInclude ProjectionType = "INCLUDE"
)

// IsValid returns true if the ProjectionType is a valid DynamoDB projection type.
func (pt ProjectionType) IsValid() bool {
	return pt == ProjectionAll || pt == ProjectionKeysOnly || pt == ProjectionInclude
}

// String returns the string representation of the ProjectionType.
func (pt ProjectionType) String() string {
	return string(pt)
}

// KeyAttribute represents a key attribute definition for DynamoDB tables.
type KeyAttribute struct {
	// Name is the attribute name used as a key.
	Name string
	// Type is the DynamoDB attribute type (S, N, B).
	Type KeyType
}

// Validate checks if the KeyAttribute has valid values.
func (ka KeyAttribute) Validate() error {
	if ka.Name == "" {
		return errors.New("key attribute name is required")
	}
	if !ka.Type.IsValid() {
		return fmt.Errorf("invalid key type %q: must be S, N, or B", ka.Type)
	}
	return nil
}

// GSISchema represents a Global Secondary Index definition.
type GSISchema struct {
	// IndexName is the name of the GSI.
	IndexName string
	// PartitionKey is the partition key for this GSI.
	PartitionKey KeyAttribute
	// SortKey is the optional sort key for this GSI.
	SortKey *KeyAttribute
	// Projection defines which attributes are projected into the index.
	Projection ProjectionType
}

// Validate checks if the GSISchema has valid values.
func (gsi GSISchema) Validate() error {
	if gsi.IndexName == "" {
		return errors.New("GSI index name is required")
	}
	if err := gsi.PartitionKey.Validate(); err != nil {
		return fmt.Errorf("GSI %q partition key: %w", gsi.IndexName, err)
	}
	if gsi.SortKey != nil {
		if err := gsi.SortKey.Validate(); err != nil {
			return fmt.Errorf("GSI %q sort key: %w", gsi.IndexName, err)
		}
	}
	if gsi.Projection != "" && !gsi.Projection.IsValid() {
		return fmt.Errorf("GSI %q: invalid projection type %q", gsi.IndexName, gsi.Projection)
	}
	return nil
}

// TableSchema represents a complete DynamoDB table schema definition.
type TableSchema struct {
	// TableName is the name of the DynamoDB table.
	TableName string
	// PartitionKey is the table's partition key.
	PartitionKey KeyAttribute
	// SortKey is the optional sort key for the table.
	SortKey *KeyAttribute
	// GlobalSecondaryIndexes are the GSIs for this table.
	GlobalSecondaryIndexes []GSISchema
	// TTLAttribute is the name of the attribute used for TTL.
	// Empty string means no TTL is enabled.
	TTLAttribute string
	// BillingMode is the table's billing mode.
	BillingMode BillingMode
	// Encryption is the encryption configuration for the table.
	// If nil, DynamoDB default encryption (AWS owned) is used.
	Encryption *EncryptionConfig
}

// Validate checks if the TableSchema has valid values.
func (ts TableSchema) Validate() error {
	if ts.TableName == "" {
		return errors.New("table name is required")
	}
	if err := ts.PartitionKey.Validate(); err != nil {
		return fmt.Errorf("partition key: %w", err)
	}
	if ts.SortKey != nil {
		if err := ts.SortKey.Validate(); err != nil {
			return fmt.Errorf("sort key: %w", err)
		}
	}
	for i, gsi := range ts.GlobalSecondaryIndexes {
		if err := gsi.Validate(); err != nil {
			return fmt.Errorf("GSI[%d]: %w", i, err)
		}
	}
	if ts.BillingMode != "" && !ts.BillingMode.IsValid() {
		return fmt.Errorf("invalid billing mode %q", ts.BillingMode)
	}
	if ts.Encryption != nil {
		if err := ts.Encryption.Validate(); err != nil {
			return fmt.Errorf("encryption: %w", err)
		}
	}
	return nil
}

// GSINames returns a list of all GSI names in this schema.
func (ts TableSchema) GSINames() []string {
	names := make([]string, len(ts.GlobalSecondaryIndexes))
	for i, gsi := range ts.GlobalSecondaryIndexes {
		names[i] = gsi.IndexName
	}
	return names
}

// ApprovalTableSchema returns the schema for the sentinel-requests approval table.
// This matches the schema expected by request/dynamodb.go:
//   - Partition key: id (S)
//   - GSIs: gsi-requester, gsi-status, gsi-profile (each with created_at sort key)
//   - TTL attribute: ttl
//   - Billing: PAY_PER_REQUEST
//   - Encryption: AWS managed KMS (enabled by default for security)
func ApprovalTableSchema(tableName string) TableSchema {
	createdAtSortKey := &KeyAttribute{Name: "created_at", Type: KeyTypeString}

	return TableSchema{
		TableName:    tableName,
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		GlobalSecondaryIndexes: []GSISchema{
			{
				IndexName:    "gsi-requester",
				PartitionKey: KeyAttribute{Name: "requester", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
			{
				IndexName:    "gsi-status",
				PartitionKey: KeyAttribute{Name: "status", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
			{
				IndexName:    "gsi-profile",
				PartitionKey: KeyAttribute{Name: "profile", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
		},
		TTLAttribute: "ttl",
		BillingMode:  BillingModePayPerRequest,
		Encryption:   DefaultEncryptionKMS(),
	}
}

// BreakGlassTableSchema returns the schema for the sentinel-breakglass table.
// This matches the schema expected by breakglass/dynamodb.go:
//   - Partition key: id (S)
//   - GSIs: gsi-invoker, gsi-status, gsi-profile (each with created_at sort key)
//   - TTL attribute: ttl
//   - Billing: PAY_PER_REQUEST
//   - Encryption: AWS managed KMS (enabled by default for security)
func BreakGlassTableSchema(tableName string) TableSchema {
	createdAtSortKey := &KeyAttribute{Name: "created_at", Type: KeyTypeString}

	return TableSchema{
		TableName:    tableName,
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		GlobalSecondaryIndexes: []GSISchema{
			{
				IndexName:    "gsi-invoker",
				PartitionKey: KeyAttribute{Name: "invoker", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
			{
				IndexName:    "gsi-status",
				PartitionKey: KeyAttribute{Name: "status", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
			{
				IndexName:    "gsi-profile",
				PartitionKey: KeyAttribute{Name: "profile", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
		},
		TTLAttribute: "ttl",
		BillingMode:  BillingModePayPerRequest,
		Encryption:   DefaultEncryptionKMS(),
	}
}

// SessionTableSchema returns the schema for the sentinel-sessions table.
// This matches the schema expected by session/dynamodb.go:
//   - Partition key: id (S)
//   - GSIs: gsi-user, gsi-status, gsi-profile (each with created_at sort key)
//   - GSI: gsi-server-instance (server_instance_id PK, status SK - different sort key!)
//   - TTL attribute: ttl
//   - Billing: PAY_PER_REQUEST
//   - Encryption: AWS managed KMS (enabled by default for security)
func SessionTableSchema(tableName string) TableSchema {
	createdAtSortKey := &KeyAttribute{Name: "created_at", Type: KeyTypeString}

	return TableSchema{
		TableName:    tableName,
		PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
		GlobalSecondaryIndexes: []GSISchema{
			{
				IndexName:    "gsi-user",
				PartitionKey: KeyAttribute{Name: "user", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
			{
				IndexName:    "gsi-status",
				PartitionKey: KeyAttribute{Name: "status", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
			{
				IndexName:    "gsi-profile",
				PartitionKey: KeyAttribute{Name: "profile", Type: KeyTypeString},
				SortKey:      createdAtSortKey,
				Projection:   ProjectionAll,
			},
			{
				IndexName:    "gsi-server-instance",
				PartitionKey: KeyAttribute{Name: "server_instance_id", Type: KeyTypeString},
				SortKey:      &KeyAttribute{Name: "status", Type: KeyTypeString},
				Projection:   ProjectionAll,
			},
		},
		TTLAttribute: "ttl",
		BillingMode:  BillingModePayPerRequest,
		Encryption:   DefaultEncryptionKMS(),
	}
}
