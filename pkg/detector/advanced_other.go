// +build !windows

package detector

// Non-Windows stub implementations

// CheckWMIPortConnectors is Windows-only
func (d *AdvancedDetector) CheckWMIPortConnectors() bool {
	return false
}

// CheckWMISystemInfo is Windows-only
func (d *AdvancedDetector) CheckWMISystemInfo() string {
	return ""
}

// CheckRegistryArtifacts is Windows-only
func (d *AdvancedDetector) CheckRegistryArtifacts() bool {
	return false
}

// IsDebuggerPresent checks for debugger (limited on non-Windows)
func (d *AdvancedDetector) IsDebuggerPresent() bool {
	// Could check for ptrace on Linux, but returning false for now
	return false
}

// CheckInjectedDLLs is Windows-only
func (d *AdvancedDetector) CheckInjectedDLLs() []string {
	return []string{}
}