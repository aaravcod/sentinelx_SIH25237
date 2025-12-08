package detection

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

//
// ---------- Helpers ----------
//

func run(cmd string, args ...string) string {
	out, _ := exec.Command(cmd, args...).Output()
	return strings.TrimSpace(string(out))
}

func runPS(command string) string {
	out, _ := exec.Command("powershell", "-Command", command).Output()
	return strings.TrimSpace(string(out))
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `"`)
	s = strings.TrimSuffix(s, `"`)
	s = strings.TrimPrefix(s, `'`)
	s = strings.TrimSuffix(s, `'`)
	return s
}

func readOSRelease() (pretty, name, versionID, variant, codename string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := parts[0]
		val := trimQuotes(parts[1])

		switch key {
		case "PRETTY_NAME":
			pretty = val
		case "NAME":
			name = val
		case "VERSION_ID":
			versionID = val
		case "VARIANT":
			variant = val
		case "VERSION_CODENAME":
			codename = val
		}
	}
	return
}

func readSingleLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

//
// ---------- System Info struct ----------
//

type SystemInfo struct {
	// Common summary fields
	OS             string
	DisplayVersion string
	Architecture   string
	ComputerName   string
	OSBuild        string
	Edition        string
	Processor      string
	RAM            string

	// Extra Linux details
	Distro        string
	DistroVersion string
	Kernel        string
}

//
// ---------- Public entrypoint ----------
//

func GetSystemInfo() SystemInfo {
	if runtime.GOOS == "windows" {
		return getWindowsInfo()
	}
	// Linux (Ubuntu, CentOS, etc.)
	return getLinuxInfo()
}

//
// ---------- WINDOWS DETECTION ----------
//

func getWindowsInfo() SystemInfo {
	info := SystemInfo{}

	// Raw registry values
	productName := runPS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').ProductName")
	editionID := runPS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').EditionID")
	build := runPS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber")
	ubr := runPS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').UBR")

	// Decide major version by build number (Windows 11 starts at 22000)
	major := "Windows 10"
	if buildNumber, err := strconv.Atoi(build); err == nil && buildNumber >= 22000 {
		major = "Windows 11"
	}

	// Build friendly OS name using ProductName
	productName = strings.TrimPrefix(productName, "Microsoft ")
	suffix := ""
	if strings.HasPrefix(productName, "Windows 10 ") {
		suffix = strings.TrimPrefix(productName, "Windows 10 ")
	} else if strings.HasPrefix(productName, "Windows 11 ") {
		suffix = strings.TrimPrefix(productName, "Windows 11 ")
	} else if productName != "" {
		suffix = productName
	}

	if suffix != "" {
		info.OS = major + " " + suffix // e.g. "Windows 11 Home Single Language"
	} else {
		info.OS = major + " " + editionID
	}

	// Display version (25H2 etc.)
	info.DisplayVersion = runPS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').DisplayVersion")
	if info.DisplayVersion == "" {
		info.DisplayVersion = runPS("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').ReleaseId")
	}

	// OS build (build.UBR)
	if ubr != "" {
		info.OSBuild = build + "." + ubr
	} else {
		info.OSBuild = build
	}

	info.Edition = editionID
	info.ComputerName = runPS("$env:COMPUTERNAME")
	info.Architecture = runtime.GOARCH
	info.RAM = runPS("[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2).ToString() + ' GB'")
	info.Processor = runPS("(Get-CimInstance Win32_Processor).Name")

	return info
}

//
// ---------- LINUX DETECTION (Ubuntu + CentOS) ----------
//

func getLinuxInfo() SystemInfo {
	info := SystemInfo{}

	info.Architecture = run("uname", "-m")
	info.ComputerName = run("hostname")
	info.Kernel = run("uname", "-r")
	info.OSBuild = info.Kernel

	pretty, name, versionID, variant, codename := readOSRelease()

	// Distro
	info.Distro = name
	info.DistroVersion = versionID

	// OS pretty name
	if pretty != "" {
		info.OS = pretty // e.g. "Ubuntu 24.04.1 LTS", "CentOS Stream 9"
	} else if name != "" && versionID != "" {
		info.OS = name + " " + versionID
	} else {
		// Old CentOS/RHEL fallback
		rel := readSingleLine("/etc/centos-release")
		if rel == "" {
			rel = readSingleLine("/etc/redhat-release")
		}
		info.OS = rel
	}

	// DisplayVersion:
	//  - Ubuntu: codename like "noble", "jammy"
	//  - CentOS: VERSION_ID like "9"
	if codename != "" {
		info.DisplayVersion = codename
	} else {
		info.DisplayVersion = versionID
	}

	// Edition (variant; often empty, use "-" for cleaner output)
	if variant != "" {
		info.Edition = variant
	} else {
		info.Edition = "-"
	}

	// CPU model
	cpu := run("bash", "-c", "lscpu | grep 'Model name' | head -n1 | cut -d: -f2-")
	if cpu == "" {
		cpu = run("bash", "-c", "grep 'model name' /proc/cpuinfo | head -n1 | cut -d: -f2-")
	}
	info.Processor = strings.TrimSpace(cpu)

	// Total RAM (e.g. 3.4Gi)
	info.RAM = run("bash", "-c", "free -h | awk '/Mem:/ {print $2}'")

	return info
}
