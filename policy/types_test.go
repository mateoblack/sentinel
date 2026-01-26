package policy

import "testing"

func TestVersion_IsValid(t *testing.T) {
	testCases := []struct {
		name    string
		version Version
		want    bool
	}{
		{
			name:    "valid version 1",
			version: Version("1"),
			want:    true,
		},
		{
			name:    "invalid version 2",
			version: Version("2"),
			want:    false,
		},
		{
			name:    "invalid version 99",
			version: Version("99"),
			want:    false,
		},
		{
			name:    "empty version",
			version: Version(""),
			want:    false,
		},
		{
			name:    "invalid string version",
			version: Version("v1"),
			want:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.version.IsValid()
			if got != tc.want {
				t.Errorf("Version(%q).IsValid() = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestVersion_IsCurrent(t *testing.T) {
	testCases := []struct {
		name    string
		version Version
		want    bool
	}{
		{
			name:    "version 1 is current",
			version: Version("1"),
			want:    true,
		},
		{
			name:    "version 2 is not current",
			version: Version("2"),
			want:    false,
		},
		{
			name:    "empty version is not current",
			version: Version(""),
			want:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.version.IsCurrent()
			if got != tc.want {
				t.Errorf("Version(%q).IsCurrent() = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestVersion_String(t *testing.T) {
	v := Version("1")
	if v.String() != "1" {
		t.Errorf("Version.String() = %q, want %q", v.String(), "1")
	}
}

func TestSchemaVersionConstants(t *testing.T) {
	// Verify constants are set correctly
	if SchemaVersion1 != "1" {
		t.Errorf("SchemaVersion1 = %q, want %q", SchemaVersion1, "1")
	}
	if CurrentSchemaVersion != SchemaVersion1 {
		t.Errorf("CurrentSchemaVersion = %q, want %q", CurrentSchemaVersion, SchemaVersion1)
	}

	// Verify SupportedVersions contains version 1
	found := false
	for _, v := range SupportedVersions {
		if v == "1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("SupportedVersions does not contain version 1")
	}
}
