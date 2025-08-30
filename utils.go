package main

import (
	"io/ioutil"
	"net"
	"runtime"
	"strings"

	ps "github.com/mitchellh/go-ps"
)

// collectMACAddresses gathers all MAC addresses from network interfaces
func collectMACAddresses() []string {
	var macs []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return macs
	}
	
	for _, iface := range ifaces {
		mac := iface.HardwareAddr.String()
		if mac != "" && mac != "00:00:00:00:00:00" {
			macs = append(macs, strings.ToUpper(mac))
		}
	}
	
	return macs
}

// collectDetectedFilePaths returns sandbox-related file paths that exist
func collectDetectedFilePaths() []string {
	var detectedPaths []string
	
	// Known sandbox file paths
	sandboxPaths := []string{
		`C:\windows\System32\Drivers\Vmmouse.sys`,
		`C:\windows\System32\Drivers\vm3dgl.dll`,
		`C:\windows\System32\Drivers\vmdum.dll`,
		`C:\windows\System32\Drivers\vm3dver.dll`,
		`C:\windows\System32\Drivers\vmtray.dll`,
		`C:\windows\System32\Drivers\vmci.sys`,
		`C:\windows\System32\Drivers\vmusbmouse.sys`,
		`C:\windows\System32\Drivers\vmx_svga.sys`,
		`C:\windows\System32\Drivers\vmxnet.sys`,
		`C:\windows\System32\Drivers\VMToolsHook.dll`,
		`C:\windows\System32\Drivers\vmhgfs.dll`,
		`C:\windows\System32\Drivers\vmmousever.dll`,
		`C:\windows\System32\Drivers\vmGuestLib.dll`,
		`C:\windows\System32\Drivers\VmGuestLibJava.dll`,
		`C:\windows\System32\Drivers\vmscsi.sys`,
		`C:\windows\System32\Drivers\VBoxMouse.sys`,
		`C:\windows\System32\Drivers\VBoxGuest.sys`,
		`C:\windows\System32\Drivers\VBoxSF.sys`,
		`C:\windows\System32\Drivers\VBoxVideo.sys`,
		`C:\windows\System32\vboxdisp.dll`,
		`C:\windows\System32\vboxhook.dll`,
		`C:\windows\System32\vboxmrxnp.dll`,
		`C:\windows\System32\vboxogl.dll`,
		`C:\windows\System32\vboxoglarrayspu.dll`,
		`C:\windows\System32\vboxoglcrutil.dll`,
		`C:\windows\System32\vboxoglerrorspu.dll`,
		`C:\windows\System32\vboxoglfeedbackspu.dll`,
		`C:\windows\System32\vboxoglpackspu.dll`,
		`C:\windows\System32\vboxoglpassthroughspu.dll`,
		`C:\windows\System32\vboxservice.exe`,
		`C:\windows\System32\vboxtray.exe`,
		`C:\windows\System32\VBoxControl.exe`,
	}
	
	for _, path := range sandboxPaths {
		if fileExists(path) {
			detectedPaths = append(detectedPaths, path)
		}
	}
	
	return detectedPaths
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	if _, err := ioutil.ReadFile(path); err == nil {
		return true
	}
	return false
}

// getProcessCount returns the number of running processes
func getProcessCount() int {
	processes, err := ps.Processes()
	if err != nil {
		return -1
	}
	return len(processes)
}

// getCPUCores returns the number of CPU cores
func getCPUCores() int {
	return runtime.NumCPU()
}

// getTempFileCount returns the number of files in the temp directory
func getTempFileCount() int {
	tempDir := `C:\windows\temp`
	files, err := ioutil.ReadDir(tempDir)
	if err != nil {
		return -1
	}
	return len(files)
}

// getSuspiciousProcesses identifies potentially suspicious sandbox processes
func getSuspiciousProcesses() []string {
	var suspicious []string
	knownSandboxProcesses := []string{
		"vboxservice.exe",
		"vboxtray.exe",
		"vmtoolsd.exe",
		"vmwaretray.exe",
		"vmwareuser.exe",
		"vmusrvc.exe",
		"vmsrvc.exe",
		"xenservice.exe",
		"qemu-ga.exe",
		"prl_cc.exe",
		"prl_tools.exe",
		"srvhost.exe", // Any.run specific
	}
	
	processes, err := ps.Processes()
	if err != nil {
		return suspicious
	}
	
	for _, proc := range processes {
		procName := strings.ToLower(proc.Executable())
		for _, sandboxProc := range knownSandboxProcesses {
			if procName == sandboxProc {
				suspicious = append(suspicious, procName)
			}
		}
	}
	
	return suspicious
}