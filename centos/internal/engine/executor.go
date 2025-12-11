package engine

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
    "os/exec"

	"sih2025/internal/dag"
	"sih2025/internal/platform"
	"sih2025/internal/policy"
	"sih2025/internal/state"
)

type AuditResult struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Actual   string `json:"actual"`
	Expected string `json:"expected"`
}



// --- HELPER: Get Raw System Value (The "Smart Split" Fix) ---
func getRawSystemValue(worker platform.HardenerInterface, cmd string, args []string) string {
	// 1. Intelligent Command Splitting
	realCmd := cmd
	// Remove pipe logic to run the raw data gatherer (e.g. 'sysctl ...' without '| grep')
	if strings.Contains(cmd, "|") {
		parts := strings.Split(cmd, "|")
		realCmd = strings.TrimSpace(parts[0])
	}
	// Handle 'bash -c' wrappers
	if len(args) > 1 && args[0] == "-c" {
		inner := args[1]
		if strings.Contains(inner, "|") {
			parts := strings.Split(inner, "|")
			realCmd = "bash"
			args = []string{"-c", strings.TrimSpace(parts[0])}
		}
	}

	// 2. Execute
	success, output, err := worker.RunCommand(realCmd, args, "")
	output = strings.TrimSpace(output)

	// 3. Smart Error Handling
	if !success || err != nil {
		// If it's a grep/find command that failed, it means the setting is missing
		if strings.Contains(cmd, "grep") || strings.Contains(cmd, "find") {
			if output == "" { return "Not Configured" }
		}
		// If sysctl failed, the key likely doesn't exist
		if strings.Contains(cmd, "sysctl") {
			if output == "" { return "Key Missing in Kernel" }
		}
		// Check for specific exit code 1 (Command not found vs Data not found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 && output == "" {
				return "Not Set"
			}
		}
	}

	if output == "" { return "Empty / Not Set" }
	
	// Clean up "fail" echoes from JSON checks
	if strings.Contains(strings.ToLower(output), "fail") {
		return "Vulnerable Config"
	}

	return output
}

// RunAudit executes rules
func RunAudit(pol *policy.Policy) []AuditResult {
	var results []AuditResult
	var mutex sync.Mutex

	worker := platform.GetPlatform()
	secManager := NewSecEditManager()

	layers, err := dag.SortRules(pol.Rules)
	if err != nil {
		fmt.Printf("[CRITICAL ERROR] Dependency Cycle: %v\n", err)
		return nil
	}

	for _, layer := range layers {
		var wg sync.WaitGroup
		for _, rule := range layer {
			wg.Add(1)
			go func(r policy.Rule) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				resultChan := make(chan struct {
					status string
					actual string
				}, 1)

				go func() {
					passed := false
					var err error
					actualVal := ""

					switch r.Type {
					case "command", "file_check", "file_edit":
						// Standard Check
						passed, actualVal, err = worker.RunCommand(r.Check.Cmd, r.Check.Args, r.Check.ExpectPattern)
						
						// IF FAIL: Use Smart Helper to get the REAL value instead of "fail"
						if !passed {
							rawVal := getRawSystemValue(worker, r.Check.Cmd, r.Check.Args)
							if rawVal != "Missing" && rawVal != "fail" {
								actualVal = rawVal
							}
						}

						actualVal = strings.TrimSpace(actualVal)
						if len(actualVal) > 60 { actualVal = actualVal[:57] + "..." }
						
						if passed && actualVal == "" { actualVal = "Verified Secure" }

					case "registry":
						passed, err = worker.CheckRegistry(r.Check.RegKey, r.Check.RegValue, r.Check.Expected)
						if passed { actualVal = fmt.Sprintf("%v", r.Check.Expected) } else { actualVal = "Registry Mismatch" }

					case "secedit":
						expectedStr, _ := r.Check.Expected.(string)
						passed, err = secManager.CheckUserRight(r.Check.RegKey, expectedStr)
						if passed { actualVal = "Right Assigned" } else { actualVal = "Right Missing" }
					}

					status := "FAIL"
					if err == nil && passed {
						status = "PASS"
					}
					resultChan <- struct{ status, actual string }{status, actualVal}
				}()

				var finalRes struct{ status, actual string }
				select {
				case res := <-resultChan:
					finalRes = res
				case <-ctx.Done():
					finalRes = struct{ status, actual string }{"TIMEOUT", "Check timed out"}
				}

				mutex.Lock()
				results = append(results, AuditResult{
					ID:       r.ID,
					Name:     r.Name,
					Severity: r.Severity,
					Status:   finalRes.status,
					Actual:   finalRes.actual,
					Expected: r.Check.ExpectPattern,
				})
				mutex.Unlock()
			}(rule)
		}
		wg.Wait()
	}
	return results
}

// ApplyFix performs Remediation
func ApplyFix(rule policy.Rule) error {
	worker := platform.GetPlatform()
	secManager := NewSecEditManager()

	fmt.Printf("[FIX] Automating Rule: %s\n", rule.ID)

	// --- 1. CAPTURE PREVIOUS VALUE ---
	prevValue := getRawSystemValue(worker, rule.Check.Cmd, rule.Check.Args)
	if len(prevValue) > 60 { prevValue = prevValue[:57] + "..." }

	// --- 2. DETERMINE NEW VALUE (No Truncation Here) ---
	newValue := "Applied Fix"

	if rule.Remediation.ReplaceText != "" {
		newValue = strings.TrimSpace(rule.Remediation.ReplaceText)
	} else if len(rule.Remediation.Args) > 0 {
		fullCmd := strings.Join(rule.Remediation.Args, " ")
		
		if strings.Contains(fullCmd, "=") && !strings.Contains(fullCmd, "==") {
			// Sysctl extraction
			parts := strings.Fields(fullCmd)
			for _, p := range parts {
				if strings.Contains(p, "=") && !strings.HasPrefix(p, "-") {
					newValue = p
					break
				}
			}
		} else if strings.Contains(fullCmd, "chmod") {
			parts := strings.Fields(fullCmd)
			for _, p := range parts {
				if _, err := strconv.Atoi(p); err == nil {
					newValue = "Mode: " + p
					break
				}
			}
		} else if strings.Contains(fullCmd, "modprobe") && strings.Contains(fullCmd, "/bin/true") {
			newValue = "Module Blacklisted"
		} else {
			// Clean up Bash -c noise
			if strings.Contains(fullCmd, "bash -c") {
				newValue = strings.TrimPrefix(fullCmd, "bash -c ")
			} else {
				newValue = fullCmd
			}
		}
	}

	// --- 3. LOG TO DB ---
	err := state.LogAction(rule.ID, rule.Name, prevValue, newValue)
	if err != nil { fmt.Printf("DB Log Error: %v\n", err) }

	// --- 4. APPLY ---
	switch rule.Remediation.Type {
	case "registry":
		err = worker.SetRegistry(rule.Remediation.RegKey, rule.Remediation.RegValue, rule.Remediation.Value)
	case "command":
		_, _, err = worker.RunCommand(rule.Remediation.Cmd, rule.Remediation.Args, "")
	case "file_edit", "file_append":
		err = worker.EditConfigFile(rule.Remediation.FilePath, rule.Remediation.SearchRegex, rule.Remediation.ReplaceText)
	case "secedit":
		valStr, _ := rule.Remediation.Value.(string)
		err = secManager.SetUserRight(rule.Remediation.RegKey, valStr)
	case "manual":
		if rule.Remediation.Cmd != "echo" && rule.Remediation.Cmd != "" {
			_, _, err = worker.RunCommand(rule.Remediation.Cmd, rule.Remediation.Args, "")
		} else {
			return fmt.Errorf("manual action required")
		}
	default:
		return fmt.Errorf("unknown remediation type: %s", rule.Remediation.Type)
	}

	if err != nil { return fmt.Errorf("fix failed: %v", err) }
	return nil
}

// RevertFix (Keep existing)
func RevertFix(rule policy.Rule) error {
	worker := platform.GetPlatform()
	secManager := NewSecEditManager()
	
	var err error
	switch rule.Rollback.Type {
	case "registry":
		err = worker.SetRegistry(rule.Rollback.RegKey, rule.Rollback.RegValue, rule.Rollback.Value)
	case "command":
		_, _, err = worker.RunCommand(rule.Rollback.Cmd, rule.Rollback.Args, "")
	case "file_edit":
		err = worker.EditConfigFile(rule.Rollback.FilePath, rule.Rollback.SearchRegex, rule.Rollback.ReplaceText)
	case "secedit":
		valStr, _ := rule.Rollback.Value.(string)
		err = secManager.SetUserRight(rule.Rollback.RegKey, valStr)
	default:
		return fmt.Errorf("unknown rollback type: %s", rule.Rollback.Type)
	}
	return err
}

func RevertAll(pol *policy.Policy) (string, error) {
	revertedCount := 0
	errorCount := 0

	fmt.Println("[RESET] Starting MASTER FORCE RESET...")

	for _, rule := range pol.Rules {
		fmt.Printf("   > Force Reverting: %s\n", rule.ID)
		err := RevertFix(rule)
		if err != nil {
			fmt.Printf("     [WARN] Revert issue on %s: %v\n", rule.ID, err)
			errorCount++
		} else {
			revertedCount++
		}
	}

	return fmt.Sprintf("Reset Complete. Reverted %d rules. Errors: %d", revertedCount, errorCount), nil
}