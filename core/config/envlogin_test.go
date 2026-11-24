package config

import "testing"

// The tests run with the environment login of the CLI, as cmd sets it.
func init() { SetEnvLogin(true) }

// TestEnvLoginOffByDefault: without SetEnvLogin(true), as for a program that
// imports the core, RETYC_TOKEN and the machine account variables are ignored.
func TestEnvLoginOffByDefault(t *testing.T) {
	t.Setenv(EnvTokenName, "offline-token")
	t.Setenv(EnvMachineDirName, t.TempDir())
	t.Setenv(EnvClientIDName, "client")
	SetEnvLogin(false)
	t.Cleanup(func() { SetEnvLogin(true) })

	if got := Token(); got != "" {
		t.Errorf("Token() = %q, want \"\" without opt-in", got)
	}
	if MachineMode() {
		t.Error("MachineMode() = true, want false without opt-in")
	}
	if m, err := LoadMachine(); m != nil || err != nil {
		t.Errorf("LoadMachine() = %v, %v, want nil, nil without opt-in", m, err)
	}

	SetEnvLogin(true)
	if Token() != "offline-token" || !MachineMode() {
		t.Error("with opt-in, RETYC_TOKEN and machine mode must be read")
	}
}
