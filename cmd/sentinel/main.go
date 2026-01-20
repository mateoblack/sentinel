package main

import (
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/byteness/aws-vault/v7/cli"
)

// Version is provided at compile time
var Version = "dev"

func main() {
	app := kingpin.New("sentinel", "Intent-aware access control for AWS credentials")
	app.Version(Version)

	s := cli.ConfigureSentinelGlobals(app)
	cli.ConfigureCredentialsCommand(app, s)
	cli.ConfigureSentinelExecCommand(app, s)
	cli.ConfigureRequestCommand(app, s)
	cli.ConfigureSentinelListCommand(app, s)
	cli.ConfigureCheckCommand(app, s)
	cli.ConfigureApproveCommand(app, s)
	cli.ConfigureDenyCommand(app, s)

	// Break-glass emergency access commands
	cli.ConfigureBreakGlassCommand(app, s)
	cli.ConfigureBreakGlassListCommand(app, s)
	cli.ConfigureBreakGlassCheckCommand(app, s)
	cli.ConfigureBreakGlassCloseCommand(app, s)

	// Bootstrap commands
	cli.ConfigureBootstrapCommand(app, s)
	cli.ConfigureStatusCommand(app, s)
	cli.ConfigureInitWizardCommand(app, s)

	// Enforcement commands
	cli.ConfigureEnforcePlanCommand(app, s)
	cli.ConfigureEnforceGenerateTrustPolicyCommand(app, s)

	// Audit commands
	cli.ConfigureAuditVerifyCommand(app, s)

	// Permissions command
	cli.ConfigurePermissionsCommand(app, s)
	cli.ConfigurePermissionsCheckCommand(app, s)

	// Config commands
	cli.ConfigureConfigCommand(app, s)

	// Identity commands
	cli.ConfigureWhoamiCommand(app, s)

	// Server session commands
	cli.ConfigureServerSessionsCommand(app, s)
	cli.ConfigureServerSessionCommand(app, s)
	cli.ConfigureServerRevokeCommand(app, s)

	// Shell integration commands
	cli.ConfigureShellInitCommand(app, s)

	kingpin.MustParse(app.Parse(os.Args[1:]))
}
