// +build windows

package detector

import (
	"strings"
	"unsafe"
	
	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows-specific WMI detection functions

// CheckWMIPortConnectors checks WMI for virtual port connectors
func (d *AdvancedDetector) CheckWMIPortConnectors() bool {
	type Win32_PortConnector struct {
		ExternalReferenceDesignator string
		Tag                        string
	}
	
	var dst []Win32_PortConnector
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil {
		return false
	}
	
	// Check for suspicious port connectors indicating VM
	for _, port := range dst {
		if strings.Contains(strings.ToLower(port.Tag), "virtual") ||
		   strings.Contains(strings.ToLower(port.ExternalReferenceDesignator), "virtual") {
			return true
		}
	}
	
	return false
}

// CheckWMISystemInfo retrieves system info via WMI
func (d *AdvancedDetector) CheckWMISystemInfo() string {
	type Win32_ComputerSystem struct {
		Model        string
		Manufacturer string
		SystemType   string
	}
	
	var dst []Win32_ComputerSystem
	query := wmi.CreateQuery(&dst, "")
	err := wmi.Query(query, &dst)
	if err != nil || len(dst) == 0 {
		return ""
	}
	
	return dst[0].Model + " " + dst[0].Manufacturer
}

// CheckRegistryArtifacts checks for sandbox-related registry keys
func (d *AdvancedDetector) CheckRegistryArtifacts() bool {
	// List of registry paths that indicate sandbox/VM
	sandboxKeys := []struct {
		root registry.Key
		path string
		key  string
	}{
		{registry.LOCAL_MACHINE, `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0`, "Identifier"},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Disk\Enum`, "0"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Oracle\VirtualBox Guest Additions`, ""},
		{registry.LOCAL_MACHINE, `SOFTWARE\VMware, Inc.\VMware Tools`, ""},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\VBoxGuest`, ""},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\VBoxMouse`, ""},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\VBoxService`, ""},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\VBoxSF`, ""},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\VBoxVideo`, ""},
	}
	
	for _, regKey := range sandboxKeys {
		key, err := registry.OpenKey(regKey.root, regKey.path, registry.QUERY_VALUE)
		if err == nil {
			defer key.Close()
			
			if regKey.key != "" {
				val, _, err := key.GetStringValue(regKey.key)
				if err == nil {
					valLower := strings.ToLower(val)
					if strings.Contains(valLower, "vbox") ||
					   strings.Contains(valLower, "virtualbox") ||
					   strings.Contains(valLower, "vmware") ||
					   strings.Contains(valLower, "virtual") ||
					   strings.Contains(valLower, "qemu") {
						return true
					}
				}
			} else {
				// Key exists, that's enough
				return true
			}
		}
	}
	
	return false
}

// IsDebuggerPresent checks if a debugger is attached (Windows-specific)
func (d *AdvancedDetector) IsDebuggerPresent() bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
	
	ret, _, _ := isDebuggerPresent.Call()
	return ret != 0
}

// CheckInjectedDLLs checks for common sandbox monitoring DLLs (Windows-specific)
func (d *AdvancedDetector) CheckInjectedDLLs() []string {
	var injectedDLLs []string
	
	// List of suspicious DLLs commonly injected by sandboxes
	suspiciousDLLs := []string{
		"sbiedll.dll",      // Sandboxie
		"dbghelp.dll",      // Debugging
		"api_log.dll",      // API logging
		"dir_watch.dll",    // Directory watching
		"pstorec.dll",      // Protected storage
		"vmcheck.dll",      // VM checking
		"wpespy.dll",       // API hooking
		"SxIn.dll",         // 360 Sandbox
		"Sf2.dll",          // Avast Sandbox
		"snxhk.dll",        // Avast Sandbox
		"cmdvrt32.dll",     // Comodo Sandbox
		"cmdvrt64.dll",     // Comodo Sandbox  
	}
	
	// Check if any of these DLLs are loaded
	for _, dllName := range suspiciousDLLs {
		h := windows.NewLazySystemDLL(dllName)
		if h.Handle() != 0 {
			injectedDLLs = append(injectedDLLs, dllName)
		}
	}
	
	// Also check via CreateToolhelp32Snapshot
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, 0)
	if err == nil {
		defer windows.CloseHandle(snapshot)
		
		var entry windows.ModuleEntry32
		entry.Size = uint32(unsafe.Sizeof(entry))
		
		err = windows.Module32First(snapshot, &entry)
		for err == nil {
			moduleName := windows.UTF16ToString(entry.Module[:])
			moduleNameLower := strings.ToLower(moduleName)
			
			// Check for sandbox-related modules
			if strings.Contains(moduleNameLower, "hook") ||
			   strings.Contains(moduleNameLower, "monitor") ||
			   strings.Contains(moduleNameLower, "sandbox") ||
			   strings.Contains(moduleNameLower, "api_log") {
				injectedDLLs = append(injectedDLLs, moduleName)
			}
			
			err = windows.Module32Next(snapshot, &entry)
		}
	}
	
	return injectedDLLs
}