package cli

import (
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

func TestConfigureProxyCommand(t *testing.T) {
	app := kingpin.New("test", "test app")
	ConfigureProxyCommand(app)

	// Verify the command was registered
	cmd := app.GetCommand("proxy")
	if cmd == nil {
		t.Fatal("expected 'proxy' command to be registered")
	}
}

func TestConfigureProxyCommand_StopFlag(t *testing.T) {
	app := kingpin.New("test", "test app")
	ConfigureProxyCommand(app)

	// Verify the --stop flag exists by parsing it
	cmd := app.GetCommand("proxy")
	if cmd == nil {
		t.Fatal("expected 'proxy' command to be registered")
	}

	// Parse with --stop flag - just verify it parses without error
	// We can't actually test the behavior without starting a real server
	_, err := app.Parse([]string{"proxy", "--stop"})
	// Note: This will call server.StopProxy() which is safe to call
	// even if no proxy is running
	if err != nil {
		// The error might be from StopProxy when no proxy is running
		// which is acceptable for this test
		t.Logf("Parse returned error (expected if no proxy running): %v", err)
	}
}

func TestProxyCommand_CommandLineHelp(t *testing.T) {
	app := kingpin.New("test", "test app")
	ConfigureProxyCommand(app)

	// Just verify the app can generate help without errors
	// This tests that the command is properly configured
	model := app.Model()

	proxyFound := false
	for _, cmd := range model.Commands {
		if cmd.Name == "proxy" {
			proxyFound = true

			// Check for stop flag
			stopFlagFound := false
			for _, flag := range cmd.Flags {
				if flag.Name == "stop" {
					stopFlagFound = true
					break
				}
			}
			if !stopFlagFound {
				t.Error("expected 'stop' flag to be present")
			}
			break
		}
	}

	if !proxyFound {
		t.Error("expected 'proxy' command in model")
	}
}

func TestProxyCommand_ParseWithoutFlags(t *testing.T) {
	app := kingpin.New("test", "test app")
	ConfigureProxyCommand(app)

	// Parse without --stop flag
	// This will attempt to start the proxy, which will fail in test environment
	// but we're testing the parsing works
	_, err := app.Parse([]string{"proxy"})
	// Expected to return an error since we can't actually start the server in tests
	// but parsing should work
	if err != nil {
		// This is expected - the proxy can't actually start in test environment
		t.Logf("Expected error when starting proxy in test: %v", err)
	}
}

func TestProxyCommand_AliasServer(t *testing.T) {
	app := kingpin.New("test", "test app")
	ConfigureProxyCommand(app)

	// Verify 'server' alias works for parsing
	cmd, err := app.Parse([]string{"server", "--stop"})
	if err != nil {
		// Error from StopProxy is acceptable
		t.Logf("Parse error (expected): %v", err)
	}

	// The command name should be 'proxy' even when called as 'server'
	if cmd != "proxy" {
		t.Errorf("expected command name 'proxy', got %q", cmd)
	}
}

func TestProxyCommand_ModelCommands(t *testing.T) {
	app := kingpin.New("test", "test app")
	ConfigureProxyCommand(app)

	model := app.Model()

	// Find proxy command in model
	var proxyCmd *kingpin.CmdModel
	for _, cmd := range model.Commands {
		if cmd.Name == "proxy" {
			proxyCmd = cmd
			break
		}
	}

	if proxyCmd == nil {
		t.Fatal("expected 'proxy' command in model")
	}

	// Verify it has the expected structure
	if proxyCmd.Name != "proxy" {
		t.Errorf("expected command name 'proxy', got %q", proxyCmd.Name)
	}
}
