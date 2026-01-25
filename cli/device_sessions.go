package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/byteness/aws-vault/v7/device"
	"github.com/byteness/aws-vault/v7/session"
)

// DeviceSessionsCommandInput contains the input for the device sessions command.
type DeviceSessionsCommandInput struct {
	Region       string
	TableName    string
	DeviceID     string // Required, positional arg (64-char lowercase hex)
	Status       string // Optional filter: active, revoked, expired
	Limit        int
	OutputFormat string // human, json, csv
	AWSProfile   string // For SSO credential loading

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the TableName and Region.
	Store session.Store
}

// DeviceSessionSummary represents a single session in the device sessions list output.
// Includes DeviceID field for device audit context.
type DeviceSessionSummary struct {
	ID               string    `json:"id"`
	User             string    `json:"user"`
	Profile          string    `json:"profile"`
	Status           string    `json:"status"`
	StartedAt        time.Time `json:"started_at"`
	LastAccessAt     time.Time `json:"last_access_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RequestCount     int64     `json:"request_count"`
	ServerInstanceID string    `json:"server_instance_id"`
	SourceIdentity   string    `json:"source_identity"`
	DeviceID         string    `json:"device_id,omitempty"`
}

// DeviceSessionsCommandOutput represents the JSON output from the device sessions command.
type DeviceSessionsCommandOutput struct {
	Sessions []DeviceSessionSummary `json:"sessions"`
}

// ConfigureDeviceSessionsCommand sets up the device-sessions command with kingpin.
func ConfigureDeviceSessionsCommand(app *kingpin.Application, s *Sentinel) {
	input := DeviceSessionsCommandInput{}

	cmd := app.Command("device-sessions", "List sessions for a specific device ID")

	cmd.Arg("device-id", "Device ID to query (64-char lowercase hex)").
		Required().
		StringVar(&input.DeviceID)

	cmd.Flag("region", "AWS region for DynamoDB").
		Required().
		StringVar(&input.Region)

	cmd.Flag("table", "DynamoDB table name for sessions").
		Required().
		StringVar(&input.TableName)

	cmd.Flag("status", "Filter by status (active, revoked, expired)").
		StringVar(&input.Status)

	cmd.Flag("limit", "Maximum number of results").
		Default("100").
		IntVar(&input.Limit)

	cmd.Flag("output", "Output format (human, json, csv)").
		Default("human").
		EnumVar(&input.OutputFormat, "human", "json", "csv")

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := DeviceSessionsCommand(context.Background(), input)
		app.FatalIfError(err, "device-sessions")
		return nil
	})
}

// DeviceSessionsCommand executes the device sessions command logic.
// It retrieves server sessions for a specific device ID from DynamoDB.
// On success, outputs to stdout. On failure, outputs error to stderr and returns error.
func DeviceSessionsCommand(ctx context.Context, input DeviceSessionsCommandInput) error {
	// 1. Validate device ID format (64-char lowercase hex)
	if !device.ValidateDeviceIdentifier(input.DeviceID) {
		fmt.Fprintf(os.Stderr, "Invalid device ID format: %s (must be 64 lowercase hex characters)\n", input.DeviceID)
		return fmt.Errorf("invalid device ID format: %s", input.DeviceID)
	}

	// 2. Load AWS config
	awsCfgOpts := []func(*config.LoadOptions) error{}
	if input.AWSProfile != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.AWSProfile))
	}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
		return err
	}

	// 3. Get or create store
	store := input.Store
	if store == nil {
		store = session.NewDynamoDBStore(awsCfg, input.TableName)
	}

	// 4. Query sessions by device ID
	sessions, err := store.ListByDeviceID(ctx, input.DeviceID, input.Limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list sessions for device: %v\n", err)
		return err
	}

	// 5. Apply optional status filter client-side
	if input.Status != "" {
		status := session.SessionStatus(input.Status)
		if !status.IsValid() {
			fmt.Fprintf(os.Stderr, "Invalid status: %s (valid: active, revoked, expired)\n", input.Status)
			return fmt.Errorf("invalid status: %s", input.Status)
		}
		filtered := make([]*session.ServerSession, 0, len(sessions))
		for _, sess := range sessions {
			if sess.Status == status {
				filtered = append(filtered, sess)
			}
		}
		sessions = filtered
	}

	// 6. Format output
	summaries := make([]DeviceSessionSummary, 0, len(sessions))
	for _, sess := range sessions {
		summaries = append(summaries, DeviceSessionSummary{
			ID:               sess.ID,
			User:             sess.User,
			Profile:          sess.Profile,
			Status:           string(sess.Status),
			StartedAt:        sess.StartedAt,
			LastAccessAt:     sess.LastAccessAt,
			ExpiresAt:        sess.ExpiresAt,
			RequestCount:     sess.RequestCount,
			ServerInstanceID: sess.ServerInstanceID,
			SourceIdentity:   sess.SourceIdentity,
			DeviceID:         sess.DeviceID,
		})
	}

	switch input.OutputFormat {
	case "json":
		output := DeviceSessionsCommandOutput{
			Sessions: summaries,
		}
		jsonBytes, err := json.MarshalIndent(&output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
			return err
		}
		fmt.Println(string(jsonBytes))
	case "csv":
		// CSV output for audit exports
		// Header
		fmt.Println("id,user,profile,status,started_at,last_access_at,expires_at,request_count,server_instance_id,device_id")
		for _, s := range summaries {
			fmt.Printf("%s,%s,%s,%s,%s,%s,%s,%d,%s,%s\n",
				s.ID,
				csvEscape(s.User),
				csvEscape(s.Profile),
				s.Status,
				s.StartedAt.Format(time.RFC3339),
				s.LastAccessAt.Format(time.RFC3339),
				s.ExpiresAt.Format(time.RFC3339),
				s.RequestCount,
				s.ServerInstanceID,
				s.DeviceID,
			)
		}
	default:
		// Human-readable format
		if len(summaries) == 0 {
			fmt.Printf("No sessions found for device %s\n", input.DeviceID)
			return nil
		}

		// Print header
		fmt.Printf("%-16s  %-12s  %-20s  %-8s  %-20s  %s\n",
			"ID", "User", "Profile", "Status", "Started", "Requests")
		fmt.Println("----------------  ------------  --------------------  --------  --------------------  --------")

		for _, s := range summaries {
			fmt.Printf("%-16s  %-12s  %-20s  %-8s  %-20s  %d\n",
				s.ID,
				truncateString(s.User, 12),
				truncateString(s.Profile, 20),
				s.Status,
				s.StartedAt.Format("2006-01-02 15:04:05"),
				s.RequestCount,
			)
		}
	}

	return nil
}

// DevicesCommandInput contains the input for the devices list command.
type DevicesCommandInput struct {
	Region           string
	TableName        string
	Since            string // Duration filter: "7d", "30d", etc.
	Limit            int
	ProfileThreshold int    // Threshold for HIGH_PROFILE_COUNT anomaly
	OutputFormat     string // human, json
	AWSProfile       string // For SSO credential loading

	// Store is an optional Store implementation for testing.
	// If nil, a DynamoDB store will be created using the TableName and Region.
	Store session.Store
}

// DeviceAggregation represents aggregated statistics for a single device.
type DeviceAggregation struct {
	DeviceID         string    `json:"device_id"`
	SessionCount     int       `json:"session_count"`
	UniqueUsers      []string  `json:"unique_users"`
	ProfilesAccessed []string  `json:"profiles_accessed"`
	LatestSession    time.Time `json:"latest_session"`
	Anomalies        []string  `json:"anomalies"`
}

// DevicesCommandOutput represents the JSON output from the devices command.
type DevicesCommandOutput struct {
	Devices []DeviceAggregation `json:"devices"`
}

// ConfigureDevicesCommand sets up the devices command with kingpin.
func ConfigureDevicesCommand(app *kingpin.Application, s *Sentinel) {
	input := DevicesCommandInput{}

	cmd := app.Command("devices", "List unique devices with session history")

	cmd.Flag("region", "AWS region for DynamoDB").
		Required().
		StringVar(&input.Region)

	cmd.Flag("table", "DynamoDB table name for sessions").
		Required().
		StringVar(&input.TableName)

	cmd.Flag("since", "Only show devices with sessions within this duration (e.g., 7d, 30d)").
		StringVar(&input.Since)

	cmd.Flag("limit", "Maximum number of sessions to query").
		Default("1000").
		IntVar(&input.Limit)

	cmd.Flag("profile-threshold", "Profile count threshold for HIGH_PROFILE_COUNT anomaly").
		Default("5").
		IntVar(&input.ProfileThreshold)

	cmd.Flag("output", "Output format (human, json)").
		Default("human").
		EnumVar(&input.OutputFormat, "human", "json")

	cmd.Flag("aws-profile", "AWS profile for credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		err := DevicesCommand(context.Background(), input)
		app.FatalIfError(err, "devices")
		return nil
	})
}

// DevicesCommand executes the devices command logic.
// It lists unique devices with session history and aggregated statistics.
// On success, outputs to stdout. On failure, outputs error to stderr and returns error.
func DevicesCommand(ctx context.Context, input DevicesCommandInput) error {
	// 1. Load AWS config
	awsCfgOpts := []func(*config.LoadOptions) error{}
	if input.AWSProfile != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithSharedConfigProfile(input.AWSProfile))
	}
	if input.Region != "" {
		awsCfgOpts = append(awsCfgOpts, config.WithRegion(input.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config: %v\n", err)
		return err
	}

	// 2. Get or create store
	store := input.Store
	if store == nil {
		store = session.NewDynamoDBStore(awsCfg, input.TableName)
	}

	// 3. Query sessions based on --since flag or default to active
	var sessions []*session.ServerSession
	limit := input.Limit
	if limit == 0 {
		limit = 1000
	}

	if input.Since != "" {
		// Parse --since duration
		sinceDuration, err := ParseDuration(input.Since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid --since duration: %v\n", err)
			return fmt.Errorf("invalid --since duration: %w", err)
		}
		sinceTime := time.Now().Add(-sinceDuration)

		// Query by time range
		sessions, err = store.ListByTimeRange(ctx, sinceTime, time.Now(), limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list sessions: %v\n", err)
			return err
		}
	} else {
		// Default to active sessions
		sessions, err = store.ListByStatus(ctx, session.StatusActive, limit)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list sessions: %v\n", err)
			return err
		}
	}

	// 4. Aggregate by device ID
	deviceMap := make(map[string]*deviceAggregator)
	for _, sess := range sessions {
		// Skip sessions without device ID
		if sess.DeviceID == "" {
			continue
		}

		agg, exists := deviceMap[sess.DeviceID]
		if !exists {
			agg = &deviceAggregator{
				deviceID:     sess.DeviceID,
				users:        make(map[string]bool),
				profiles:     make(map[string]bool),
				latestTime:   sess.StartedAt,
				sessionCount: 0,
			}
			deviceMap[sess.DeviceID] = agg
		}

		agg.sessionCount++
		agg.users[sess.User] = true
		agg.profiles[sess.Profile] = true
		if sess.StartedAt.After(agg.latestTime) {
			agg.latestTime = sess.StartedAt
		}
	}

	// 5. Convert to output format with anomaly detection
	profileThreshold := input.ProfileThreshold
	if profileThreshold == 0 {
		profileThreshold = 5
	}

	devices := make([]DeviceAggregation, 0, len(deviceMap))
	for deviceID, agg := range deviceMap {
		users := make([]string, 0, len(agg.users))
		for u := range agg.users {
			users = append(users, u)
		}
		sort.Strings(users)

		profiles := make([]string, 0, len(agg.profiles))
		for p := range agg.profiles {
			profiles = append(profiles, p)
		}
		sort.Strings(profiles)

		// Detect anomalies
		var anomalies []string
		if len(users) > 1 {
			anomalies = append(anomalies, "MULTI_USER")
		}
		if len(profiles) > profileThreshold {
			anomalies = append(anomalies, "HIGH_PROFILE_COUNT")
		}

		devices = append(devices, DeviceAggregation{
			DeviceID:         deviceID,
			SessionCount:     agg.sessionCount,
			UniqueUsers:      users,
			ProfilesAccessed: profiles,
			LatestSession:    agg.latestTime,
			Anomalies:        anomalies,
		})
	}

	// Sort by latest session (most recent first)
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].LatestSession.After(devices[j].LatestSession)
	})

	// 6. Format output
	switch input.OutputFormat {
	case "json":
		output := DevicesCommandOutput{
			Devices: devices,
		}
		jsonBytes, err := json.MarshalIndent(&output, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal output to JSON: %v\n", err)
			return err
		}
		fmt.Println(string(jsonBytes))
	default:
		// Human-readable format
		if len(devices) == 0 {
			fmt.Println("No devices found with session history.")
			return nil
		}

		// Print header
		fmt.Printf("%-20s  %8s  %5s  %8s  %-20s  %s\n",
			"Device ID (truncated)", "Sessions", "Users", "Profiles", "Latest Access", "Flags")
		fmt.Println("--------------------  --------  -----  --------  --------------------  -----")

		for _, d := range devices {
			flags := ""
			if len(d.Anomalies) > 0 {
				flags = joinStrings(d.Anomalies, ",")
			}

			fmt.Printf("%-20s  %8d  %5d  %8d  %-20s  %s\n",
				truncateString(d.DeviceID, 20),
				d.SessionCount,
				len(d.UniqueUsers),
				len(d.ProfilesAccessed),
				d.LatestSession.Format("2006-01-02 15:04:05"),
				flags,
			)
		}
	}

	return nil
}

// deviceAggregator is a helper struct for aggregating device statistics.
type deviceAggregator struct {
	deviceID     string
	sessionCount int
	users        map[string]bool
	profiles     map[string]bool
	latestTime   time.Time
}

// joinStrings joins strings with a separator.
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
