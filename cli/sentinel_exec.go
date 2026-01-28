package cli

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/device"
)

// SentinelExecCommandInput contains the input for the sentinel exec command.
// Note: Classic mode and CLI server mode have been removed in v1.22.
// Only --remote-server (Lambda TVM) mode is supported.
type SentinelExecCommandInput struct {
	ProfileName  string   // AWS profile to request from TVM
	Command      string   // Command to execute
	Args         []string // Command arguments
	Region       string   // AWS region (passed to subprocess environment)
	RemoteServer string   // Remote TVM URL for credential vending (required)
}

// ConfigureSentinelExecCommand sets up the sentinel exec command with kingpin.
// Note: Classic mode and CLI server mode have been removed in v1.22.
// Only --remote-server (Lambda TVM) mode is supported.
func ConfigureSentinelExecCommand(app *kingpin.Application, s *Sentinel) {
	input := SentinelExecCommandInput{}

	cmd := app.Command("exec", "Execute a command with TVM-vended AWS credentials. Uses Lambda Token Vending Machine (TVM) for server-side credential vending.")

	cmd.Flag("profile", "Name of the AWS profile to request from TVM").
		Required().
		StringVar(&input.ProfileName)

	cmd.Flag("remote-server", "TVM Lambda Function URL (e.g., https://xxx.lambda-url.region.on.aws). Deploy with: sentinel tvm deploy").
		Required().
		StringVar(&input.RemoteServer)

	cmd.Flag("region", "The AWS region (passed to subprocess environment)").
		StringVar(&input.Region)

	cmd.Arg("cmd", "Command to execute, defaults to $SHELL").
		StringVar(&input.Command)

	cmd.Arg("args", "Command arguments").
		StringsVar(&input.Args)

	cmd.Action(func(c *kingpin.ParseContext) error {
		exitcode, err := SentinelExecCommand(context.Background(), input, s)
		app.FatalIfError(err, "exec")
		if exitcode != 0 {
			os.Exit(exitcode)
		}
		return nil
	})
}

// SentinelExecCommand executes the sentinel exec command logic.
// It evaluates policy before spawning a subprocess with credentials.
// Returns exit code and error.
func SentinelExecCommand(ctx context.Context, input SentinelExecCommandInput, s *Sentinel) (int, error) {
	// 0. Check if already in a sentinel subshell
	if os.Getenv("AWS_SENTINEL") != "" {
		return 0, fmt.Errorf("running in an existing sentinel subshell; 'exit' from the subshell or unset AWS_SENTINEL to force")
	}

	// 0.5. Require --remote-server - TVM is the only supported mode
	if input.RemoteServer == "" {
		tvmErr := fmt.Errorf(`sentinel exec requires --remote-server <url>

Classic mode has been removed in v1.22. Sentinel now requires server-side
credential vending through Lambda TVM for verified security.

To set up TVM:
1. Deploy the Lambda TVM: sentinel tvm deploy --region us-east-1
2. Configure your profile: sentinel config set tvm-url <url>
3. Run: sentinel exec --remote-server <url> --profile %s -- <command>

See: https://github.com/avishayil/sentinel/blob/main/docs/TVM_SETUP.md`, input.ProfileName)
		fmt.Fprintf(os.Stderr, "Error: %v\n", tvmErr)
		return 1, tvmErr
	}

	// Handle remote TVM mode - the only supported credential vending path
	{
		// Remote TVM mode - credentials come from external TVM
		// TVM handles policy evaluation, so skip local profile validation
		// The profile parameter specifies which profile to request from TVM

		// Collect device ID for MDM-based posture verification
		// TVM will use this to query MDM for actual device posture
		deviceID, deviceErr := device.GetDeviceID()
		if deviceErr != nil {
			log.Printf("Warning: failed to collect device ID: %v (continuing without device posture)", deviceErr)
		}

		// Build TVM URL with device_id if available
		tvmURL := input.RemoteServer
		if deviceID != "" {
			parsedURL, parseErr := url.Parse(input.RemoteServer)
			if parseErr != nil {
				log.Printf("Warning: failed to parse remote server URL: %v", parseErr)
			} else {
				queryParams := parsedURL.Query()
				queryParams.Set("device_id", deviceID)
				parsedURL.RawQuery = queryParams.Encode()
				tvmURL = parsedURL.String()
				log.Printf("Including device_id in remote TVM request")
			}
		}

		// Default to shell if no command specified
		command := input.Command
		if command == "" {
			command = getDefaultShell()
		}

		// Prepare subprocess environment
		cmdEnv := createEnv(input.ProfileName, input.Region, "")

		// Set AWS_CONTAINER_CREDENTIALS_FULL_URI to point to TVM
		// AWS SDK handles credential refresh automatically
		cmdEnv.Set("AWS_CONTAINER_CREDENTIALS_FULL_URI", tvmURL)

		// Prevent AWS SDK from reading config files - use container credentials only
		cmdEnv.Set("AWS_CONFIG_FILE", "/dev/null")
		cmdEnv.Set("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")

		log.Printf("Using remote TVM at %s for profile %s", input.RemoteServer, input.ProfileName)

		return runSubProcess(command, input.Args, cmdEnv)
	}
}
