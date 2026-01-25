package infrastructure

import (
	"strings"
	"testing"
)

// TestKeyTypeIsValid tests KeyType validation.
func TestKeyTypeIsValid(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		expected bool
	}{
		{"string type valid", KeyTypeString, true},
		{"number type valid", KeyTypeNumber, true},
		{"binary type valid", KeyTypeBinary, true},
		{"empty type invalid", KeyType(""), false},
		{"lowercase s invalid", KeyType("s"), false},
		{"invalid type X", KeyType("X"), false},
		{"invalid type string", KeyType("string"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.keyType.IsValid()
			if got != tt.expected {
				t.Errorf("KeyType(%q).IsValid() = %v, want %v", tt.keyType, got, tt.expected)
			}
		})
	}
}

// TestKeyTypeString tests KeyType string conversion.
func TestKeyTypeString(t *testing.T) {
	tests := []struct {
		keyType  KeyType
		expected string
	}{
		{KeyTypeString, "S"},
		{KeyTypeNumber, "N"},
		{KeyTypeBinary, "B"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.keyType.String()
			if got != tt.expected {
				t.Errorf("KeyType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestBillingModeIsValid tests BillingMode validation.
func TestBillingModeIsValid(t *testing.T) {
	tests := []struct {
		name     string
		mode     BillingMode
		expected bool
	}{
		{"pay per request valid", BillingModePayPerRequest, true},
		{"provisioned valid", BillingModeProvisioned, true},
		{"empty mode invalid", BillingMode(""), false},
		{"invalid mode", BillingMode("INVALID"), false},
		{"lowercase pay per request", BillingMode("pay_per_request"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.IsValid()
			if got != tt.expected {
				t.Errorf("BillingMode(%q).IsValid() = %v, want %v", tt.mode, got, tt.expected)
			}
		})
	}
}

// TestBillingModeString tests BillingMode string conversion.
func TestBillingModeString(t *testing.T) {
	tests := []struct {
		mode     BillingMode
		expected string
	}{
		{BillingModePayPerRequest, "PAY_PER_REQUEST"},
		{BillingModeProvisioned, "PROVISIONED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.expected {
				t.Errorf("BillingMode.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestProjectionTypeIsValid tests ProjectionType validation.
func TestProjectionTypeIsValid(t *testing.T) {
	tests := []struct {
		name     string
		proj     ProjectionType
		expected bool
	}{
		{"all valid", ProjectionAll, true},
		{"keys only valid", ProjectionKeysOnly, true},
		{"include valid", ProjectionInclude, true},
		{"empty invalid", ProjectionType(""), false},
		{"lowercase all invalid", ProjectionType("all"), false},
		{"invalid type", ProjectionType("INVALID"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.proj.IsValid()
			if got != tt.expected {
				t.Errorf("ProjectionType(%q).IsValid() = %v, want %v", tt.proj, got, tt.expected)
			}
		})
	}
}

// TestProjectionTypeString tests ProjectionType string conversion.
func TestProjectionTypeString(t *testing.T) {
	tests := []struct {
		proj     ProjectionType
		expected string
	}{
		{ProjectionAll, "ALL"},
		{ProjectionKeysOnly, "KEYS_ONLY"},
		{ProjectionInclude, "INCLUDE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.proj.String()
			if got != tt.expected {
				t.Errorf("ProjectionType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestKeyAttributeValidate tests KeyAttribute validation.
func TestKeyAttributeValidate(t *testing.T) {
	tests := []struct {
		name      string
		attr      KeyAttribute
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid string key",
			attr:    KeyAttribute{Name: "id", Type: KeyTypeString},
			wantErr: false,
		},
		{
			name:    "valid number key",
			attr:    KeyAttribute{Name: "sort_key", Type: KeyTypeNumber},
			wantErr: false,
		},
		{
			name:    "valid binary key",
			attr:    KeyAttribute{Name: "hash", Type: KeyTypeBinary},
			wantErr: false,
		},
		{
			name:      "empty name fails",
			attr:      KeyAttribute{Name: "", Type: KeyTypeString},
			wantErr:   true,
			errSubstr: "name is required",
		},
		{
			name:      "invalid type fails",
			attr:      KeyAttribute{Name: "id", Type: KeyType("X")},
			wantErr:   true,
			errSubstr: "invalid key type",
		},
		{
			name:      "empty type fails",
			attr:      KeyAttribute{Name: "id", Type: KeyType("")},
			wantErr:   true,
			errSubstr: "invalid key type",
		},
		{
			name:      "lowercase type fails",
			attr:      KeyAttribute{Name: "id", Type: KeyType("s")},
			wantErr:   true,
			errSubstr: "must be S, N, or B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attr.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("KeyAttribute.Validate() = nil, want error containing %q", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("KeyAttribute.Validate() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Errorf("KeyAttribute.Validate() = %v, want nil", err)
			}
		})
	}
}

// TestGSISchemaValidate tests GSISchema validation.
func TestGSISchemaValidate(t *testing.T) {
	tests := []struct {
		name      string
		gsi       GSISchema
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid GSI with partition key only",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
				Projection:   ProjectionAll,
			},
			wantErr: false,
		},
		{
			name: "valid GSI with partition and sort key",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
				SortKey:      &KeyAttribute{Name: "sk", Type: KeyTypeString},
				Projection:   ProjectionKeysOnly,
			},
			wantErr: false,
		},
		{
			name: "valid GSI with empty projection (defaults)",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
			},
			wantErr: false,
		},
		{
			name: "empty index name fails",
			gsi: GSISchema{
				IndexName:    "",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
			},
			wantErr:   true,
			errSubstr: "index name is required",
		},
		{
			name: "invalid partition key type fails",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyType("X")},
			},
			wantErr:   true,
			errSubstr: "partition key",
		},
		{
			name: "empty partition key name fails",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "", Type: KeyTypeString},
			},
			wantErr:   true,
			errSubstr: "partition key",
		},
		{
			name: "invalid sort key type fails",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
				SortKey:      &KeyAttribute{Name: "sk", Type: KeyType("X")},
			},
			wantErr:   true,
			errSubstr: "sort key",
		},
		{
			name: "empty sort key name fails",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
				SortKey:      &KeyAttribute{Name: "", Type: KeyTypeString},
			},
			wantErr:   true,
			errSubstr: "sort key",
		},
		{
			name: "invalid projection type fails",
			gsi: GSISchema{
				IndexName:    "gsi-test",
				PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
				Projection:   ProjectionType("INVALID"),
			},
			wantErr:   true,
			errSubstr: "invalid projection type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.gsi.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("GSISchema.Validate() = nil, want error containing %q", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("GSISchema.Validate() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Errorf("GSISchema.Validate() = %v, want nil", err)
			}
		})
	}
}

// TestTableSchemaValidate tests TableSchema validation.
func TestTableSchemaValidate(t *testing.T) {
	validGSI := GSISchema{
		IndexName:    "gsi-test",
		PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
		Projection:   ProjectionAll,
	}
	invalidGSI := GSISchema{
		IndexName:    "",
		PartitionKey: KeyAttribute{Name: "pk", Type: KeyTypeString},
	}

	tests := []struct {
		name      string
		schema    TableSchema
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid complete schema",
			schema: TableSchema{
				TableName:              "test-table",
				PartitionKey:           KeyAttribute{Name: "id", Type: KeyTypeString},
				SortKey:                &KeyAttribute{Name: "sk", Type: KeyTypeString},
				GlobalSecondaryIndexes: []GSISchema{validGSI},
				TTLAttribute:           "ttl",
				BillingMode:            BillingModePayPerRequest,
			},
			wantErr: false,
		},
		{
			name: "valid minimal schema",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
			},
			wantErr: false,
		},
		{
			name: "valid schema without GSIs",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				TTLAttribute: "",
				BillingMode:  BillingModeProvisioned,
			},
			wantErr: false,
		},
		{
			name: "empty TTL attribute allowed",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				TTLAttribute: "",
			},
			wantErr: false,
		},
		{
			name: "empty billing mode allowed (defaults)",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				BillingMode:  "",
			},
			wantErr: false,
		},
		{
			name: "missing table name fails",
			schema: TableSchema{
				TableName:    "",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
			},
			wantErr:   true,
			errSubstr: "table name is required",
		},
		{
			name: "missing partition key name fails",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "", Type: KeyTypeString},
			},
			wantErr:   true,
			errSubstr: "partition key",
		},
		{
			name: "invalid partition key type fails",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyType("X")},
			},
			wantErr:   true,
			errSubstr: "partition key",
		},
		{
			name: "invalid sort key type fails",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				SortKey:      &KeyAttribute{Name: "sk", Type: KeyType("X")},
			},
			wantErr:   true,
			errSubstr: "sort key",
		},
		{
			name: "invalid GSI fails",
			schema: TableSchema{
				TableName:              "test-table",
				PartitionKey:           KeyAttribute{Name: "id", Type: KeyTypeString},
				GlobalSecondaryIndexes: []GSISchema{invalidGSI},
			},
			wantErr:   true,
			errSubstr: "GSI[0]",
		},
		{
			name: "invalid billing mode fails",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				BillingMode:  BillingMode("INVALID"),
			},
			wantErr:   true,
			errSubstr: "invalid billing mode",
		},
		{
			name: "multiple GSIs with one invalid fails",
			schema: TableSchema{
				TableName:              "test-table",
				PartitionKey:           KeyAttribute{Name: "id", Type: KeyTypeString},
				GlobalSecondaryIndexes: []GSISchema{validGSI, invalidGSI},
			},
			wantErr:   true,
			errSubstr: "GSI[1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.schema.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("TableSchema.Validate() = nil, want error containing %q", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("TableSchema.Validate() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Errorf("TableSchema.Validate() = %v, want nil", err)
			}
		})
	}
}

// TestTableSchemaGSINames tests the GSINames method.
func TestTableSchemaGSINames(t *testing.T) {
	tests := []struct {
		name     string
		schema   TableSchema
		expected []string
	}{
		{
			name: "returns all GSI names",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				GlobalSecondaryIndexes: []GSISchema{
					{IndexName: "gsi-1", PartitionKey: KeyAttribute{Name: "a", Type: KeyTypeString}},
					{IndexName: "gsi-2", PartitionKey: KeyAttribute{Name: "b", Type: KeyTypeString}},
					{IndexName: "gsi-3", PartitionKey: KeyAttribute{Name: "c", Type: KeyTypeString}},
				},
			},
			expected: []string{"gsi-1", "gsi-2", "gsi-3"},
		},
		{
			name: "returns empty slice for no GSIs",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.schema.GSINames()
			if len(got) != len(tt.expected) {
				t.Errorf("GSINames() returned %d names, want %d", len(got), len(tt.expected))
				return
			}
			for i, name := range got {
				if name != tt.expected[i] {
					t.Errorf("GSINames()[%d] = %q, want %q", i, name, tt.expected[i])
				}
			}
		})
	}
}

// TestApprovalTableSchema tests the predefined approval table schema.
func TestApprovalTableSchema(t *testing.T) {
	tableName := "sentinel-requests"
	schema := ApprovalTableSchema(tableName)

	// Test table name
	if schema.TableName != tableName {
		t.Errorf("TableName = %q, want %q", schema.TableName, tableName)
	}

	// Test partition key
	if schema.PartitionKey.Name != "id" {
		t.Errorf("PartitionKey.Name = %q, want %q", schema.PartitionKey.Name, "id")
	}
	if schema.PartitionKey.Type != KeyTypeString {
		t.Errorf("PartitionKey.Type = %q, want %q", schema.PartitionKey.Type, KeyTypeString)
	}

	// Test no sort key on main table
	if schema.SortKey != nil {
		t.Errorf("SortKey = %v, want nil", schema.SortKey)
	}

	// Test TTL attribute
	if schema.TTLAttribute != "ttl" {
		t.Errorf("TTLAttribute = %q, want %q", schema.TTLAttribute, "ttl")
	}

	// Test billing mode
	if schema.BillingMode != BillingModePayPerRequest {
		t.Errorf("BillingMode = %q, want %q", schema.BillingMode, BillingModePayPerRequest)
	}

	// Test encryption - should default to KMS
	if schema.Encryption == nil {
		t.Error("Encryption = nil, want non-nil (KMS encryption)")
	} else if schema.Encryption.Type != EncryptionKMS {
		t.Errorf("Encryption.Type = %q, want %q", schema.Encryption.Type, EncryptionKMS)
	}

	// Test GSIs
	expectedGSIs := map[string]struct {
		partitionKey string
		sortKey      string
	}{
		"gsi-requester": {partitionKey: "requester", sortKey: "created_at"},
		"gsi-status":    {partitionKey: "status", sortKey: "created_at"},
		"gsi-profile":   {partitionKey: "profile", sortKey: "created_at"},
	}

	if len(schema.GlobalSecondaryIndexes) != len(expectedGSIs) {
		t.Errorf("GSI count = %d, want %d", len(schema.GlobalSecondaryIndexes), len(expectedGSIs))
	}

	for _, gsi := range schema.GlobalSecondaryIndexes {
		expected, ok := expectedGSIs[gsi.IndexName]
		if !ok {
			t.Errorf("unexpected GSI %q", gsi.IndexName)
			continue
		}

		if gsi.PartitionKey.Name != expected.partitionKey {
			t.Errorf("GSI %q partition key = %q, want %q", gsi.IndexName, gsi.PartitionKey.Name, expected.partitionKey)
		}
		if gsi.PartitionKey.Type != KeyTypeString {
			t.Errorf("GSI %q partition key type = %q, want %q", gsi.IndexName, gsi.PartitionKey.Type, KeyTypeString)
		}

		if gsi.SortKey == nil {
			t.Errorf("GSI %q sort key = nil, want non-nil", gsi.IndexName)
		} else {
			if gsi.SortKey.Name != expected.sortKey {
				t.Errorf("GSI %q sort key = %q, want %q", gsi.IndexName, gsi.SortKey.Name, expected.sortKey)
			}
			if gsi.SortKey.Type != KeyTypeString {
				t.Errorf("GSI %q sort key type = %q, want %q", gsi.IndexName, gsi.SortKey.Type, KeyTypeString)
			}
		}

		if gsi.Projection != ProjectionAll {
			t.Errorf("GSI %q projection = %q, want %q", gsi.IndexName, gsi.Projection, ProjectionAll)
		}
	}

	// Test that schema passes validation
	if err := schema.Validate(); err != nil {
		t.Errorf("ApprovalTableSchema validation failed: %v", err)
	}
}

// TestApprovalTableSchemaGSINames tests GSI names match request/dynamodb.go constants.
func TestApprovalTableSchemaGSINames(t *testing.T) {
	schema := ApprovalTableSchema("test-table")
	gsiNames := schema.GSINames()

	// These constants match request/dynamodb.go
	expectedNames := []string{"gsi-requester", "gsi-status", "gsi-profile"}

	if len(gsiNames) != len(expectedNames) {
		t.Errorf("GSINames() returned %d names, want %d", len(gsiNames), len(expectedNames))
		return
	}

	// Check each expected name is present
	nameSet := make(map[string]bool)
	for _, name := range gsiNames {
		nameSet[name] = true
	}

	for _, expected := range expectedNames {
		if !nameSet[expected] {
			t.Errorf("GSINames() missing expected GSI %q", expected)
		}
	}
}

// TestBreakGlassTableSchema tests the predefined break-glass table schema.
func TestBreakGlassTableSchema(t *testing.T) {
	tableName := "sentinel-breakglass"
	schema := BreakGlassTableSchema(tableName)

	// Test table name
	if schema.TableName != tableName {
		t.Errorf("TableName = %q, want %q", schema.TableName, tableName)
	}

	// Test partition key
	if schema.PartitionKey.Name != "id" {
		t.Errorf("PartitionKey.Name = %q, want %q", schema.PartitionKey.Name, "id")
	}
	if schema.PartitionKey.Type != KeyTypeString {
		t.Errorf("PartitionKey.Type = %q, want %q", schema.PartitionKey.Type, KeyTypeString)
	}

	// Test no sort key on main table
	if schema.SortKey != nil {
		t.Errorf("SortKey = %v, want nil", schema.SortKey)
	}

	// Test TTL attribute
	if schema.TTLAttribute != "ttl" {
		t.Errorf("TTLAttribute = %q, want %q", schema.TTLAttribute, "ttl")
	}

	// Test billing mode
	if schema.BillingMode != BillingModePayPerRequest {
		t.Errorf("BillingMode = %q, want %q", schema.BillingMode, BillingModePayPerRequest)
	}

	// Test encryption - should default to KMS
	if schema.Encryption == nil {
		t.Error("Encryption = nil, want non-nil (KMS encryption)")
	} else if schema.Encryption.Type != EncryptionKMS {
		t.Errorf("Encryption.Type = %q, want %q", schema.Encryption.Type, EncryptionKMS)
	}

	// Test GSIs - key difference is gsi-invoker instead of gsi-requester
	expectedGSIs := map[string]struct {
		partitionKey string
		sortKey      string
	}{
		"gsi-invoker": {partitionKey: "invoker", sortKey: "created_at"},
		"gsi-status":  {partitionKey: "status", sortKey: "created_at"},
		"gsi-profile": {partitionKey: "profile", sortKey: "created_at"},
	}

	if len(schema.GlobalSecondaryIndexes) != len(expectedGSIs) {
		t.Errorf("GSI count = %d, want %d", len(schema.GlobalSecondaryIndexes), len(expectedGSIs))
	}

	for _, gsi := range schema.GlobalSecondaryIndexes {
		expected, ok := expectedGSIs[gsi.IndexName]
		if !ok {
			t.Errorf("unexpected GSI %q", gsi.IndexName)
			continue
		}

		if gsi.PartitionKey.Name != expected.partitionKey {
			t.Errorf("GSI %q partition key = %q, want %q", gsi.IndexName, gsi.PartitionKey.Name, expected.partitionKey)
		}
		if gsi.PartitionKey.Type != KeyTypeString {
			t.Errorf("GSI %q partition key type = %q, want %q", gsi.IndexName, gsi.PartitionKey.Type, KeyTypeString)
		}

		if gsi.SortKey == nil {
			t.Errorf("GSI %q sort key = nil, want non-nil", gsi.IndexName)
		} else {
			if gsi.SortKey.Name != expected.sortKey {
				t.Errorf("GSI %q sort key = %q, want %q", gsi.IndexName, gsi.SortKey.Name, expected.sortKey)
			}
			if gsi.SortKey.Type != KeyTypeString {
				t.Errorf("GSI %q sort key type = %q, want %q", gsi.IndexName, gsi.SortKey.Type, KeyTypeString)
			}
		}

		if gsi.Projection != ProjectionAll {
			t.Errorf("GSI %q projection = %q, want %q", gsi.IndexName, gsi.Projection, ProjectionAll)
		}
	}

	// Test that schema passes validation
	if err := schema.Validate(); err != nil {
		t.Errorf("BreakGlassTableSchema validation failed: %v", err)
	}
}

// TestBreakGlassTableSchemaGSINames tests GSI names match breakglass/dynamodb.go constants.
func TestBreakGlassTableSchemaGSINames(t *testing.T) {
	schema := BreakGlassTableSchema("test-table")
	gsiNames := schema.GSINames()

	// These constants match breakglass/dynamodb.go: GSIInvoker, GSIStatus, GSIProfile
	expectedNames := []string{"gsi-invoker", "gsi-status", "gsi-profile"}

	if len(gsiNames) != len(expectedNames) {
		t.Errorf("GSINames() returned %d names, want %d", len(gsiNames), len(expectedNames))
		return
	}

	// Check each expected name is present
	nameSet := make(map[string]bool)
	for _, name := range gsiNames {
		nameSet[name] = true
	}

	for _, expected := range expectedNames {
		if !nameSet[expected] {
			t.Errorf("GSINames() missing expected GSI %q", expected)
		}
	}
}

// TestSessionTableSchema tests the predefined session table schema.
func TestSessionTableSchema(t *testing.T) {
	tableName := "sentinel-sessions"
	schema := SessionTableSchema(tableName)

	// Test table name
	if schema.TableName != tableName {
		t.Errorf("TableName = %q, want %q", schema.TableName, tableName)
	}

	// Test partition key
	if schema.PartitionKey.Name != "id" {
		t.Errorf("PartitionKey.Name = %q, want %q", schema.PartitionKey.Name, "id")
	}
	if schema.PartitionKey.Type != KeyTypeString {
		t.Errorf("PartitionKey.Type = %q, want %q", schema.PartitionKey.Type, KeyTypeString)
	}

	// Test no sort key on main table
	if schema.SortKey != nil {
		t.Errorf("SortKey = %v, want nil", schema.SortKey)
	}

	// Test TTL attribute
	if schema.TTLAttribute != "ttl" {
		t.Errorf("TTLAttribute = %q, want %q", schema.TTLAttribute, "ttl")
	}

	// Test billing mode
	if schema.BillingMode != BillingModePayPerRequest {
		t.Errorf("BillingMode = %q, want %q", schema.BillingMode, BillingModePayPerRequest)
	}

	// Test encryption - should default to KMS
	if schema.Encryption == nil {
		t.Error("Encryption = nil, want non-nil (KMS encryption)")
	} else if schema.Encryption.Type != EncryptionKMS {
		t.Errorf("Encryption.Type = %q, want %q", schema.Encryption.Type, EncryptionKMS)
	}

	// Test GSI count - session table has 4 GSIs (1 more than approval/breakglass)
	expectedGSICount := 4
	if len(schema.GlobalSecondaryIndexes) != expectedGSICount {
		t.Errorf("GSI count = %d, want %d", len(schema.GlobalSecondaryIndexes), expectedGSICount)
	}

	// Test GSIs - note gsi-server-instance has different sort key (status, not created_at)
	expectedGSIs := map[string]struct {
		partitionKey string
		sortKey      string
	}{
		"gsi-user":            {partitionKey: "user", sortKey: "created_at"},
		"gsi-status":          {partitionKey: "status", sortKey: "created_at"},
		"gsi-profile":         {partitionKey: "profile", sortKey: "created_at"},
		"gsi-server-instance": {partitionKey: "server_instance_id", sortKey: "status"},
	}

	for _, gsi := range schema.GlobalSecondaryIndexes {
		expected, ok := expectedGSIs[gsi.IndexName]
		if !ok {
			t.Errorf("unexpected GSI %q", gsi.IndexName)
			continue
		}

		if gsi.PartitionKey.Name != expected.partitionKey {
			t.Errorf("GSI %q partition key = %q, want %q", gsi.IndexName, gsi.PartitionKey.Name, expected.partitionKey)
		}
		if gsi.PartitionKey.Type != KeyTypeString {
			t.Errorf("GSI %q partition key type = %q, want %q", gsi.IndexName, gsi.PartitionKey.Type, KeyTypeString)
		}

		if gsi.SortKey == nil {
			t.Errorf("GSI %q sort key = nil, want non-nil", gsi.IndexName)
		} else {
			if gsi.SortKey.Name != expected.sortKey {
				t.Errorf("GSI %q sort key = %q, want %q", gsi.IndexName, gsi.SortKey.Name, expected.sortKey)
			}
			if gsi.SortKey.Type != KeyTypeString {
				t.Errorf("GSI %q sort key type = %q, want %q", gsi.IndexName, gsi.SortKey.Type, KeyTypeString)
			}
		}

		if gsi.Projection != ProjectionAll {
			t.Errorf("GSI %q projection = %q, want %q", gsi.IndexName, gsi.Projection, ProjectionAll)
		}
	}

	// Test that schema passes validation
	if err := schema.Validate(); err != nil {
		t.Errorf("SessionTableSchema validation failed: %v", err)
	}
}

// TestSessionTableSchemaGSINames tests GSI names match session/dynamodb.go constants.
func TestSessionTableSchemaGSINames(t *testing.T) {
	schema := SessionTableSchema("test-table")
	gsiNames := schema.GSINames()

	// These constants match session/dynamodb.go: GSIUser, GSIStatus, GSIProfile, GSIServerInstance
	expectedNames := []string{"gsi-user", "gsi-status", "gsi-profile", "gsi-server-instance"}

	if len(gsiNames) != len(expectedNames) {
		t.Errorf("GSINames() returned %d names, want %d", len(gsiNames), len(expectedNames))
		return
	}

	// Check each expected name is present
	nameSet := make(map[string]bool)
	for _, name := range gsiNames {
		nameSet[name] = true
	}

	for _, expected := range expectedNames {
		if !nameSet[expected] {
			t.Errorf("GSINames() missing expected GSI %q", expected)
		}
	}
}

// TestSessionTableSchemaGSIServerInstanceSortKey tests the unique sort key for gsi-server-instance.
// This GSI uses status as sort key (not created_at like other GSIs) for FindActiveByServerInstance queries.
func TestSessionTableSchemaGSIServerInstanceSortKey(t *testing.T) {
	schema := SessionTableSchema("test-table")

	// Find gsi-server-instance
	var serverInstanceGSI *GSISchema
	for i := range schema.GlobalSecondaryIndexes {
		if schema.GlobalSecondaryIndexes[i].IndexName == "gsi-server-instance" {
			serverInstanceGSI = &schema.GlobalSecondaryIndexes[i]
			break
		}
	}

	if serverInstanceGSI == nil {
		t.Fatal("gsi-server-instance not found in schema")
	}

	// Verify partition key is server_instance_id
	if serverInstanceGSI.PartitionKey.Name != "server_instance_id" {
		t.Errorf("gsi-server-instance partition key = %q, want %q",
			serverInstanceGSI.PartitionKey.Name, "server_instance_id")
	}

	// Verify sort key is status (not created_at)
	if serverInstanceGSI.SortKey == nil {
		t.Fatal("gsi-server-instance sort key = nil, want non-nil")
	}
	if serverInstanceGSI.SortKey.Name != "status" {
		t.Errorf("gsi-server-instance sort key = %q, want %q",
			serverInstanceGSI.SortKey.Name, "status")
	}
}

// ============================================================================
// Encryption Configuration Tests
// ============================================================================

// TestEncryptionTypeIsValid tests EncryptionType validation.
func TestEncryptionTypeIsValid(t *testing.T) {
	tests := []struct {
		name     string
		encType  EncryptionType
		expected bool
	}{
		{"default encryption valid", EncryptionDefault, true},
		{"KMS encryption valid", EncryptionKMS, true},
		{"customer key encryption valid", EncryptionCustomerKey, true},
		{"empty type invalid", EncryptionType(""), false},
		{"lowercase default invalid", EncryptionType("default"), false},
		{"invalid type", EncryptionType("INVALID"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.encType.IsValid()
			if got != tt.expected {
				t.Errorf("EncryptionType(%q).IsValid() = %v, want %v", tt.encType, got, tt.expected)
			}
		})
	}
}

// TestEncryptionTypeString tests EncryptionType string conversion.
func TestEncryptionTypeString(t *testing.T) {
	tests := []struct {
		encType  EncryptionType
		expected string
	}{
		{EncryptionDefault, "DEFAULT"},
		{EncryptionKMS, "KMS"},
		{EncryptionCustomerKey, "CUSTOMER_KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.encType.String()
			if got != tt.expected {
				t.Errorf("EncryptionType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestEncryptionConfigValidate tests EncryptionConfig validation.
func TestEncryptionConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		config    EncryptionConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "valid default encryption",
			config:  EncryptionConfig{Type: EncryptionDefault},
			wantErr: false,
		},
		{
			name:    "valid KMS encryption",
			config:  EncryptionConfig{Type: EncryptionKMS},
			wantErr: false,
		},
		{
			name: "valid customer key encryption",
			config: EncryptionConfig{
				Type:      EncryptionCustomerKey,
				KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			},
			wantErr: false,
		},
		{
			name: "valid customer key encryption with alias",
			config: EncryptionConfig{
				Type:      EncryptionCustomerKey,
				KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:alias/my-key",
			},
			wantErr: false,
		},
		{
			name:      "invalid encryption type fails",
			config:   EncryptionConfig{Type: EncryptionType("INVALID")},
			wantErr:  true,
			errSubstr: "invalid encryption type",
		},
		{
			name:      "default encryption with KMSKeyARN fails",
			config:   EncryptionConfig{Type: EncryptionDefault, KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/123"},
			wantErr:  true,
			errSubstr: "KMSKeyARN must be empty",
		},
		{
			name:      "KMS encryption with KMSKeyARN fails",
			config:   EncryptionConfig{Type: EncryptionKMS, KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/123"},
			wantErr:  true,
			errSubstr: "KMSKeyARN must be empty",
		},
		{
			name:      "customer key encryption without KMSKeyARN fails",
			config:   EncryptionConfig{Type: EncryptionCustomerKey},
			wantErr:  true,
			errSubstr: "KMSKeyARN is required",
		},
		{
			name:      "customer key encryption with invalid ARN fails",
			config:   EncryptionConfig{Type: EncryptionCustomerKey, KMSKeyARN: "invalid-arn"},
			wantErr:  true,
			errSubstr: "invalid KMSKeyARN format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("EncryptionConfig.Validate() = nil, want error containing %q", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("EncryptionConfig.Validate() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Errorf("EncryptionConfig.Validate() = %v, want nil", err)
			}
		})
	}
}

// TestDefaultEncryptionKMS tests the DefaultEncryptionKMS helper function.
func TestDefaultEncryptionKMS(t *testing.T) {
	config := DefaultEncryptionKMS()

	if config == nil {
		t.Fatal("DefaultEncryptionKMS() = nil, want non-nil")
	}

	if config.Type != EncryptionKMS {
		t.Errorf("DefaultEncryptionKMS().Type = %q, want %q", config.Type, EncryptionKMS)
	}

	if config.KMSKeyARN != "" {
		t.Errorf("DefaultEncryptionKMS().KMSKeyARN = %q, want empty", config.KMSKeyARN)
	}

	// Verify it passes validation
	if err := config.Validate(); err != nil {
		t.Errorf("DefaultEncryptionKMS().Validate() = %v, want nil", err)
	}
}

// TestTableSchemaValidateWithEncryption tests TableSchema validation with encryption configuration.
func TestTableSchemaValidateWithEncryption(t *testing.T) {
	tests := []struct {
		name      string
		schema    TableSchema
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid schema with KMS encryption",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				Encryption:   DefaultEncryptionKMS(),
			},
			wantErr: false,
		},
		{
			name: "valid schema with default encryption",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				Encryption:   &EncryptionConfig{Type: EncryptionDefault},
			},
			wantErr: false,
		},
		{
			name: "valid schema with customer key encryption",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				Encryption: &EncryptionConfig{
					Type:      EncryptionCustomerKey,
					KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
				},
			},
			wantErr: false,
		},
		{
			name: "valid schema with nil encryption (backward compatible)",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				Encryption:   nil,
			},
			wantErr: false,
		},
		{
			name: "invalid encryption config in schema fails",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				Encryption:   &EncryptionConfig{Type: EncryptionType("INVALID")},
			},
			wantErr:   true,
			errSubstr: "encryption",
		},
		{
			name: "customer key without ARN in schema fails",
			schema: TableSchema{
				TableName:    "test-table",
				PartitionKey: KeyAttribute{Name: "id", Type: KeyTypeString},
				Encryption:   &EncryptionConfig{Type: EncryptionCustomerKey},
			},
			wantErr:   true,
			errSubstr: "encryption",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.schema.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("TableSchema.Validate() = nil, want error containing %q", tt.errSubstr)
				} else if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("TableSchema.Validate() error = %q, want error containing %q", err.Error(), tt.errSubstr)
				}
			} else if err != nil {
				t.Errorf("TableSchema.Validate() = %v, want nil", err)
			}
		})
	}
}
