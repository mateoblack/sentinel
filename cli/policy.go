package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/byteness/aws-vault/v7/bootstrap"
	"github.com/byteness/aws-vault/v7/policy"
)

// PolicyPullCommandInput contains the input for policy pull.
type PolicyPullCommandInput struct {
	Profile         string // Positional arg - the AWS profile name to pull policy for
	PolicyRoot      string // --policy-root flag, default bootstrap.DefaultPolicyRoot
	PolicyParameter string // --policy-parameter flag, explicit SSM path override
	OutputFile      string // --output / -o flag, empty = stdout
	Region          string // --region flag for SSM operations
	AWSProfile      string // --aws-profile flag for credentials

	// For testing
	Stdout    *os.File
	Stderr    *os.File
	SSMClient policy.SSMAPI // For testing, nil = create from AWS config
}

// PolicyPushCommandInput contains the input for policy push.
type PolicyPushCommandInput struct {
	Profile         string // Positional arg - target profile
	InputFile       string // Positional arg - path to policy YAML file
	PolicyRoot      string // --policy-root flag, default bootstrap.DefaultPolicyRoot
	PolicyParameter string // --policy-parameter flag, explicit SSM path override
	Region          string // --region flag for SSM operations
	AWSProfile      string // --aws-profile flag for credentials
	NoBackup        bool   // --no-backup flag, skip fetching existing policy as backup
	Force           bool   // --force flag, skip confirmation prompt

	// For testing
	Stdin     io.Reader     // For testing confirmation input
	Stdout    *os.File      // Not used currently, but for consistency
	Stderr    *os.File      // For output messages
	SSMClient policy.SSMAPI // For testing, nil = create from AWS config
}

// PolicyDiffCommandInput contains the input for policy diff.
type PolicyDiffCommandInput struct {
	Profile         string // Positional arg - target profile
	InputFile       string // Positional arg - path to local policy YAML file
	PolicyRoot      string // --policy-root flag, default bootstrap.DefaultPolicyRoot
	PolicyParameter string // --policy-parameter flag, explicit SSM path override
	Region          string // --region flag for SSM operations
	AWSProfile      string // --aws-profile flag for credentials
	NoColor         bool   // --no-color flag, disable colorized output

	// For testing
	Stdout    *os.File
	Stderr    *os.File
	SSMClient policy.SSMAPI // For testing, nil = create from AWS config
}

// policyCmd holds the policy command reference for subcommand registration.
var policyCmd *kingpin.CmdClause

// ConfigurePolicyCommand sets up the policy command with its subcommands.
func ConfigurePolicyCommand(app *kingpin.Application, s *Sentinel) {
	policyCmd = app.Command("policy", "Policy management commands")

	input := PolicyPullCommandInput{}

	cmd := policyCmd.Command("pull", "Pull policy from SSM Parameter Store")

	cmd.Arg("profile", "AWS profile name to pull policy for").
		Required().
		StringVar(&input.Profile)

	cmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&input.PolicyRoot)

	cmd.Flag("policy-parameter", "Explicit SSM parameter path (overrides profile-based path)").
		StringVar(&input.PolicyParameter)

	cmd.Flag("output", "Output file path (omit for stdout)").
		Short('o').
		StringVar(&input.OutputFile)

	cmd.Flag("region", "AWS region for SSM operations").
		StringVar(&input.Region)

	cmd.Flag("aws-profile", "AWS profile for SSM credentials (optional, uses default chain if not specified)").
		StringVar(&input.AWSProfile)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PolicyPullCommand(context.Background(), input)
		if err != nil {
			app.FatalIfError(err, "policy pull")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})

	// Configure push subcommand
	pushInput := PolicyPushCommandInput{}

	pushCmd := policyCmd.Command("push", "Push policy to SSM Parameter Store")

	pushCmd.Arg("profile", "Target profile name for the policy").
		Required().
		StringVar(&pushInput.Profile)

	pushCmd.Arg("input-file", "Path to policy YAML file").
		Required().
		StringVar(&pushInput.InputFile)

	pushCmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&pushInput.PolicyRoot)

	pushCmd.Flag("policy-parameter", "Explicit SSM parameter path (overrides profile-based path)").
		StringVar(&pushInput.PolicyParameter)

	pushCmd.Flag("region", "AWS region for SSM operations").
		StringVar(&pushInput.Region)

	pushCmd.Flag("aws-profile", "AWS profile for SSM credentials (optional, uses default chain if not specified)").
		StringVar(&pushInput.AWSProfile)

	pushCmd.Flag("no-backup", "Skip fetching existing policy as backup").
		BoolVar(&pushInput.NoBackup)

	pushCmd.Flag("force", "Skip confirmation prompt").
		Short('f').
		BoolVar(&pushInput.Force)

	pushCmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PolicyPushCommand(context.Background(), pushInput)
		if err != nil {
			app.FatalIfError(err, "policy push")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})

	// Configure diff subcommand
	diffInput := PolicyDiffCommandInput{}

	diffCmd := policyCmd.Command("diff", "Show pending changes between local file and SSM policy")

	diffCmd.Arg("profile", "Target profile name for the policy").
		Required().
		StringVar(&diffInput.Profile)

	diffCmd.Arg("input-file", "Path to local policy YAML file").
		Required().
		StringVar(&diffInput.InputFile)

	diffCmd.Flag("policy-root", "SSM parameter path prefix for policies").
		Default(bootstrap.DefaultPolicyRoot).
		StringVar(&diffInput.PolicyRoot)

	diffCmd.Flag("policy-parameter", "Explicit SSM parameter path (overrides profile-based path)").
		StringVar(&diffInput.PolicyParameter)

	diffCmd.Flag("region", "AWS region for SSM operations").
		StringVar(&diffInput.Region)

	diffCmd.Flag("aws-profile", "AWS profile for SSM credentials (optional, uses default chain if not specified)").
		StringVar(&diffInput.AWSProfile)

	diffCmd.Flag("no-color", "Disable colorized output").
		BoolVar(&diffInput.NoColor)

	diffCmd.Action(func(c *kingpin.ParseContext) error {
		exitCode, err := PolicyDiffCommand(context.Background(), diffInput)
		if err != nil {
			app.FatalIfError(err, "policy diff")
		}
		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	})
}

// PolicyPullCommand executes the policy pull command logic.
// It returns exit code (0=success, 1=error) and any fatal error.
func PolicyPullCommand(ctx context.Context, input PolicyPullCommandInput) (int, error) {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Determine SSM parameter path
	parameterPath := input.PolicyParameter
	if parameterPath == "" {
		parameterPath = bootstrap.DefaultPolicyParameterName(input.PolicyRoot, input.Profile)
	}

	// Create policy loader
	var loader *policy.Loader
	if input.SSMClient != nil {
		// Use injected client for testing
		loader = policy.NewLoaderWithClient(input.SSMClient)
	} else {
		// Load AWS config
		var opts []func(*awsconfig.LoadOptions) error
		if input.AWSProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			opts = append(opts, awsconfig.WithRegion(input.Region))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config: %v\n", err)
			fmt.Fprintf(stderr, "\nSuggestion: check AWS credentials and region configuration\n")
			return 1, nil
		}
		loader = policy.NewLoader(awsCfg)
	}

	// Load policy from SSM
	pol, err := loader.Load(ctx, parameterPath)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			fmt.Fprintf(stderr, "Error: policy not found at %s\n", parameterPath)
			fmt.Fprintf(stderr, "\nSuggestion: verify the SSM parameter exists and you have ssm:GetParameter permission\n")
			fmt.Fprintf(stderr, "You can create a policy using: sentinel bootstrap plan --policy-root %s\n", input.PolicyRoot)
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to load policy: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify AWS credentials and SSM permissions\n")
		return 1, nil
	}

	// Marshal policy to YAML
	yamlData, err := policy.MarshalPolicy(pol)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to marshal policy: %v\n", err)
		return 1, nil
	}

	// Output policy
	if input.OutputFile != "" {
		// Write to file
		if err := os.WriteFile(input.OutputFile, yamlData, 0644); err != nil {
			fmt.Fprintf(stderr, "Error: failed to write file: %v\n", err)
			return 1, nil
		}
		fmt.Fprintf(stderr, "Policy written to %s\n", input.OutputFile)
	} else {
		// Write to stdout (clean, no prefix)
		fmt.Fprint(stdout, string(yamlData))
	}

	return 0, nil
}

// PolicyPushCommand executes the policy push command logic.
// It validates the policy, optionally fetches backup, prompts for confirmation,
// and uploads to SSM Parameter Store.
// Returns exit code (0=success, 1=error) and any fatal error.
func PolicyPushCommand(ctx context.Context, input PolicyPushCommandInput) (int, error) {
	// Set up I/O
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	stdin := input.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}

	// Read policy file from disk
	policyData, err := os.ReadFile(input.InputFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "Error: file not found: %s\n", input.InputFile)
			fmt.Fprintf(stderr, "\nSuggestion: verify the file path is correct\n")
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to read file: %v\n", err)
		return 1, nil
	}

	// Validate policy using policy.ValidatePolicy(data)
	if err := policy.ValidatePolicy(policyData); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: fix the policy YAML and try again\n")
		return 1, nil
	}

	// Determine SSM parameter path
	parameterPath := input.PolicyParameter
	if parameterPath == "" {
		parameterPath = bootstrap.DefaultPolicyParameterName(input.PolicyRoot, input.Profile)
	}

	// Create SSM client
	var ssmClient policy.SSMAPI
	if input.SSMClient != nil {
		ssmClient = input.SSMClient
	} else {
		var opts []func(*awsconfig.LoadOptions) error
		if input.AWSProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			opts = append(opts, awsconfig.WithRegion(input.Region))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config: %v\n", err)
			fmt.Fprintf(stderr, "\nSuggestion: check AWS credentials and region configuration\n")
			return 1, nil
		}
		ssmClient = ssm.NewFromConfig(awsCfg)
	}

	// Fetch existing policy as backup (unless --no-backup)
	backupExists := false
	if !input.NoBackup {
		output, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name:           aws.String(parameterPath),
			WithDecryption: aws.Bool(true),
		})
		if err != nil {
			var notFound *types.ParameterNotFound
			if !errors.As(err, &notFound) {
				// Real error, not just "not found"
				fmt.Fprintf(stderr, "Warning: failed to fetch existing policy for backup: %v\n", err)
			}
			// Not found is fine - this is a new parameter
		} else {
			backupExists = true
			fmt.Fprintf(stderr, "Existing policy found (version %d)\n", output.Parameter.Version)
		}
	}

	// Confirmation prompt (unless --force)
	if !input.Force {
		fmt.Fprintf(stderr, "\n")
		fmt.Fprintf(stderr, "Parameter path: %s\n", parameterPath)
		if backupExists {
			fmt.Fprintf(stderr, "Status: updating existing policy\n")
		} else {
			fmt.Fprintf(stderr, "Status: creating new policy\n")
		}
		fmt.Fprintf(stderr, "\n")
		fmt.Fprintf(stderr, "Proceed? [y/N]: ")

		reader := bufio.NewReader(stdin)
		response, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(stderr, "\nError: failed to read input: %v\n", err)
			return 1, nil
		}

		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Fprintf(stderr, "Cancelled.\n")
			return 0, nil
		}
	}

	// Call PutParameter with Overwrite=true
	_, err = ssmClient.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(parameterPath),
		Value:     aws.String(string(policyData)),
		Type:      types.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to write policy to SSM: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: verify AWS credentials and ssm:PutParameter permission\n")
		return 1, nil
	}

	fmt.Fprintf(stderr, "Policy successfully pushed to %s\n", parameterPath)
	return 0, nil
}

// PolicyDiffCommand shows pending changes between a local policy file and the SSM-stored policy.
// It returns exit code 0 if no changes exist, 1 if changes exist (for scripting).
// Fatal errors return an error.
func PolicyDiffCommand(ctx context.Context, input PolicyDiffCommandInput) (int, error) {
	// Set up I/O
	stdout := input.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := input.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	// Read local policy file from disk
	localData, err := os.ReadFile(input.InputFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "Error: file not found: %s\n", input.InputFile)
			fmt.Fprintf(stderr, "\nSuggestion: verify the file path is correct\n")
			return 1, nil
		}
		fmt.Fprintf(stderr, "Error: failed to read file: %v\n", err)
		return 1, nil
	}

	// Validate local policy using policy.ValidatePolicy(data) - fail early on invalid YAML
	if err := policy.ValidatePolicy(localData); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		fmt.Fprintf(stderr, "\nSuggestion: fix the policy YAML and try again\n")
		return 1, nil
	}

	// Determine SSM parameter path
	parameterPath := input.PolicyParameter
	if parameterPath == "" {
		parameterPath = bootstrap.DefaultPolicyParameterName(input.PolicyRoot, input.Profile)
	}

	// Create SSM client or use injected one
	var ssmClient policy.SSMAPI
	if input.SSMClient != nil {
		ssmClient = input.SSMClient
	} else {
		var opts []func(*awsconfig.LoadOptions) error
		if input.AWSProfile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(input.AWSProfile))
		}
		if input.Region != "" {
			opts = append(opts, awsconfig.WithRegion(input.Region))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to load AWS config: %v\n", err)
			fmt.Fprintf(stderr, "\nSuggestion: check AWS credentials and region configuration\n")
			return 1, nil
		}
		ssmClient = ssm.NewFromConfig(awsCfg)
	}

	// Fetch remote policy from SSM
	var remoteData []byte
	remoteNotFound := false

	output, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(parameterPath),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		var notFound *types.ParameterNotFound
		if errors.As(err, &notFound) {
			remoteNotFound = true
		} else {
			fmt.Fprintf(stderr, "Error: failed to fetch remote policy: %v\n", err)
			fmt.Fprintf(stderr, "\nSuggestion: verify AWS credentials and ssm:GetParameter permission\n")
			return 1, nil
		}
	} else {
		remoteData = []byte(aws.ToString(output.Parameter.Value))
	}

	// Normalize both policies by parsing and re-marshaling for consistent formatting
	localNormalized, err := normalizePolicy(localData)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to normalize local policy: %v\n", err)
		return 1, nil
	}

	var remoteNormalized string
	if !remoteNotFound {
		remoteNormalizedBytes, err := normalizePolicy(remoteData)
		if err != nil {
			fmt.Fprintf(stderr, "Error: failed to normalize remote policy: %v\n", err)
			return 1, nil
		}
		remoteNormalized = remoteNormalizedBytes
	}

	// Generate unified diff
	diff := generateUnifiedDiff(remoteNormalized, localNormalized, parameterPath, input.InputFile)

	// If no changes, exit 0 with no output
	if diff == "" {
		return 0, nil
	}

	// Output diff with optional coloring
	if input.NoColor {
		fmt.Fprint(stdout, diff)
	} else {
		fmt.Fprint(stdout, colorizeDiff(diff))
	}

	// Exit code 1 indicates changes exist (for scripting)
	return 1, nil
}

// normalizePolicy parses and re-marshals a policy to ensure consistent formatting.
func normalizePolicy(data []byte) (string, error) {
	p, err := policy.ParsePolicy(data)
	if err != nil {
		return "", err
	}
	normalized, err := policy.MarshalPolicy(p)
	if err != nil {
		return "", err
	}
	return string(normalized), nil
}

// generateUnifiedDiff produces a unified diff between two strings.
// Returns empty string if no differences.
func generateUnifiedDiff(old, new, oldLabel, newLabel string) string {
	oldLines := splitLines(old)
	newLines := splitLines(new)

	// Simple line-by-line diff using longest common subsequence approach
	edits := computeEdits(oldLines, newLines)

	if len(edits) == 0 {
		return ""
	}

	var result strings.Builder

	// Header
	result.WriteString(fmt.Sprintf("--- a/%s\n", oldLabel))
	result.WriteString(fmt.Sprintf("+++ b/%s\n", newLabel))

	// Generate hunks
	hunks := groupEditsIntoHunks(edits, oldLines, newLines)
	for _, hunk := range hunks {
		result.WriteString(hunk)
	}

	return result.String()
}

// edit represents a diff operation
type edit struct {
	kind    editKind
	oldLine int // 0-indexed line in old
	newLine int // 0-indexed line in new
	text    string
}

type editKind int

const (
	editEqual editKind = iota
	editDelete
	editInsert
)

// splitLines splits a string into lines, handling empty strings
func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	// Remove trailing newline to avoid empty last element
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return []string{}
	}
	return strings.Split(s, "\n")
}

// computeEdits computes the edits needed to transform old into new
func computeEdits(old, new []string) []edit {
	// Compute LCS (longest common subsequence)
	lcs := computeLCS(old, new)

	var edits []edit
	oi, ni, li := 0, 0, 0

	for oi < len(old) || ni < len(new) {
		if li < len(lcs) && oi < len(old) && ni < len(new) && old[oi] == lcs[li] && new[ni] == lcs[li] {
			// Common line
			edits = append(edits, edit{kind: editEqual, oldLine: oi, newLine: ni, text: old[oi]})
			oi++
			ni++
			li++
		} else if oi < len(old) && (li >= len(lcs) || old[oi] != lcs[li]) {
			// Delete from old
			edits = append(edits, edit{kind: editDelete, oldLine: oi, text: old[oi]})
			oi++
		} else if ni < len(new) && (li >= len(lcs) || new[ni] != lcs[li]) {
			// Insert from new
			edits = append(edits, edit{kind: editInsert, newLine: ni, text: new[ni]})
			ni++
		}
	}

	return edits
}

// computeLCS computes the longest common subsequence of two string slices
func computeLCS(a, b []string) []string {
	m, n := len(a), len(b)
	// DP table
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] > dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}

	// Backtrack to find LCS
	lcsLen := dp[m][n]
	lcs := make([]string, lcsLen)
	i, j := m, n
	for i > 0 && j > 0 {
		if a[i-1] == b[j-1] {
			lcsLen--
			lcs[lcsLen] = a[i-1]
			i--
			j--
		} else if dp[i-1][j] > dp[i][j-1] {
			i--
		} else {
			j--
		}
	}

	return lcs
}

// groupEditsIntoHunks groups edits into unified diff hunks with context
func groupEditsIntoHunks(edits []edit, oldLines, newLines []string) []string {
	const contextLines = 3

	var hunks []string
	var currentHunk strings.Builder

	// Find ranges of changes
	type changeRange struct {
		start int
		end   int
	}

	var ranges []changeRange
	inChange := false
	changeStart := 0

	for i, e := range edits {
		if e.kind != editEqual {
			if !inChange {
				inChange = true
				changeStart = i
			}
		} else {
			if inChange {
				ranges = append(ranges, changeRange{start: changeStart, end: i})
				inChange = false
			}
		}
	}
	if inChange {
		ranges = append(ranges, changeRange{start: changeStart, end: len(edits)})
	}

	if len(ranges) == 0 {
		return nil
	}

	// Merge ranges that are close together and generate hunks
	mergedRanges := mergeCloseRanges(ranges, contextLines*2, len(edits))

	for _, r := range mergedRanges {
		// Calculate context bounds
		contextStart := r.start - contextLines
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := r.end + contextLines
		if contextEnd > len(edits) {
			contextEnd = len(edits)
		}

		// Calculate line numbers for hunk header
		oldStart, oldCount := 0, 0
		newStart, newCount := 0, 0
		firstOld, firstNew := true, true

		for i := contextStart; i < contextEnd; i++ {
			e := edits[i]
			switch e.kind {
			case editEqual:
				if firstOld {
					oldStart = e.oldLine + 1
					firstOld = false
				}
				if firstNew {
					newStart = e.newLine + 1
					firstNew = false
				}
				oldCount++
				newCount++
			case editDelete:
				if firstOld {
					oldStart = e.oldLine + 1
					firstOld = false
				}
				oldCount++
			case editInsert:
				if firstNew {
					newStart = e.newLine + 1
					firstNew = false
				}
				newCount++
			}
		}

		// Handle edge case for empty old or new
		if oldStart == 0 {
			oldStart = 1
		}
		if newStart == 0 {
			newStart = 1
		}

		currentHunk.Reset()
		currentHunk.WriteString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", oldStart, oldCount, newStart, newCount))

		for i := contextStart; i < contextEnd; i++ {
			e := edits[i]
			switch e.kind {
			case editEqual:
				currentHunk.WriteString(" " + e.text + "\n")
			case editDelete:
				currentHunk.WriteString("-" + e.text + "\n")
			case editInsert:
				currentHunk.WriteString("+" + e.text + "\n")
			}
		}

		hunks = append(hunks, currentHunk.String())
	}

	return hunks
}

// mergeCloseRanges merges change ranges that are within gap lines of each other
func mergeCloseRanges(ranges []changeRange, gap, maxLen int) []changeRange {
	if len(ranges) == 0 {
		return nil
	}

	merged := []changeRange{ranges[0]}
	for i := 1; i < len(ranges); i++ {
		last := &merged[len(merged)-1]
		if ranges[i].start-last.end <= gap {
			last.end = ranges[i].end
		} else {
			merged = append(merged, ranges[i])
		}
	}
	return merged
}

// colorizeDiff adds ANSI color codes to diff output
func colorizeDiff(diff string) string {
	const (
		colorReset = "\033[0m"
		colorRed   = "\033[31m"
		colorGreen = "\033[32m"
		colorCyan  = "\033[36m"
		colorBold  = "\033[1m"
	)

	lines := strings.Split(diff, "\n")
	var result strings.Builder

	for _, line := range lines {
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			result.WriteString(colorBold + line + colorReset + "\n")
		} else if strings.HasPrefix(line, "@@") {
			result.WriteString(colorCyan + line + colorReset + "\n")
		} else if strings.HasPrefix(line, "-") {
			result.WriteString(colorRed + line + colorReset + "\n")
		} else if strings.HasPrefix(line, "+") {
			result.WriteString(colorGreen + line + colorReset + "\n")
		} else if line != "" {
			result.WriteString(line + "\n")
		}
	}

	// Remove trailing newline if original didn't have it
	output := result.String()
	if !strings.HasSuffix(diff, "\n") && strings.HasSuffix(output, "\n") {
		output = strings.TrimSuffix(output, "\n")
	}

	return output
}
