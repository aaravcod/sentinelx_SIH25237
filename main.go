package main

import (
	"fmt"
	"os-hardener/internal/detection"
)

func main() {
	fmt.Println("===== SYSTEM INFORMATION =====")

	info := detection.GetSystemInfo()

	fmt.Println("Operating System :", info.OS)
	fmt.Println("Display Version  :", info.DisplayVersion)
	fmt.Println("Architecture     :", info.Architecture)
	fmt.Println("Computer Name    :", info.ComputerName)
	fmt.Println("OS Build         :", info.OSBuild)
	fmt.Println("Edition          :", info.Edition)
	fmt.Println("Processor        :", info.Processor)
	fmt.Println("RAM Memory       :", info.RAM)

	if info.OS != "" && info.Distro != "" {
		fmt.Println("\n--- Linux Details ---")
		fmt.Println("Distro           :", info.Distro)
		fmt.Println("Version          :", info.DistroVersion)
		fmt.Println("Kernel           :", info.Kernel)
	}
}
