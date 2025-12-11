package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"sih2025/internal/engine"
	"sih2025/internal/policy"
	"sih2025/internal/report"
	"sih2025/internal/state"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

func main() {
	distro := "Windows"
	if runtime.GOOS == "linux" {
		distro = getLinuxDistro()
	}

	fmt.Println("==================================================")
	fmt.Printf("   SIH 2025 HARDENING ORCHESTRATOR (v2.0)\n")
	fmt.Printf("   DETECTED OS: %s\n", strings.ToUpper(distro))
	fmt.Println("==================================================")

	initDB()
	startServer()
}

func initDB() {
	state.InitDB()
	fmt.Println("[SUCCESS] State Manager Ready (Rollback Enabled)")
}

func startServer() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.LoadHTMLGlob("ui/templates/*")
	r.Static("/static", "./ui/static")

	r.GET("/", func(c *gin.Context) { c.HTML(200, "index.html", nil) })

	api := r.Group("/api")
	{
		// 1. STATUS (Updated to show Distro)
		api.GET("/status", func(c *gin.Context) {
			osName := runtime.GOOS
			if osName == "linux" {
				osName = getLinuxDistro()
			}
			c.JSON(200, gin.H{"status": "online", "os": osName})
		})

		// 2. SCAN
		api.GET("/scan", func(c *gin.Context) {
			profile := c.DefaultQuery("level", "strict")
			fmt.Printf("[API] Scanning with Profile: %s\n", profile)

			pol := loadCurrentPolicy()
			if pol == nil {
				c.JSON(500, gin.H{"error": "Failed to load policy"})
				return
			}

			// FILTER LOGIC
			filteredRules := []policy.Rule{}
			for _, rule := range pol.Rules {
				if profile == "strict" {
					filteredRules = append(filteredRules, rule)
				} else if profile == "moderate" {
					if rule.Severity == "Critical" || rule.Severity == "High" || rule.Severity == "Medium" {
						filteredRules = append(filteredRules, rule)
					}
				} else if profile == "basic" {
					if rule.Severity == "Critical" || rule.Severity == "High" {
						filteredRules = append(filteredRules, rule)
					}
				}
			}
			pol.Rules = filteredRules

			results := engine.RunAudit(pol)
			c.JSON(200, gin.H{"results": results})
		})

		// 3. FIX
		api.POST("/fix", func(c *gin.Context) {
			var req struct {
				ID string `json:"id"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			pol := loadCurrentPolicy()
			for _, rule := range pol.Rules {
				if rule.ID == req.ID {
					if err := engine.ApplyFix(rule); err != nil {
						c.JSON(500, gin.H{"error": err.Error()})
						return
					}
					c.JSON(200, gin.H{"status": "fixed", "id": req.ID})
					return
				}
			}
			c.JSON(404, gin.H{"error": "Rule not found"})
		})

		// 4. ROLLBACK
		api.POST("/rollback", func(c *gin.Context) {
			var req struct {
				ID string `json:"id"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			pol := loadCurrentPolicy()
			for _, rule := range pol.Rules {
				if rule.ID == req.ID {
					if err := engine.RevertFix(rule); err != nil {
						c.JSON(500, gin.H{"error": err.Error()})
						return
					}
					c.JSON(200, gin.H{"status": "rolled_back", "id": req.ID})
					return
				}
			}
			c.JSON(404, gin.H{"error": "Rule not found"})
		})

		// 5. EXPORT REPORT (With Dynamic Label)
		api.GET("/export", func(c *gin.Context) {
			profile := c.DefaultQuery("level", "strict")
			pol := loadCurrentPolicy()

			filteredRules := []policy.Rule{}
			for _, rule := range pol.Rules {
				if profile == "strict" {
					filteredRules = append(filteredRules, rule)
				} else if profile == "moderate" {
					if rule.Severity == "Critical" || rule.Severity == "High" || rule.Severity == "Medium" {
						filteredRules = append(filteredRules, rule)
					}
				} else if profile == "basic" {
					if rule.Severity == "Critical" || rule.Severity == "High" {
						filteredRules = append(filteredRules, rule)
					}
				}
			}
			pol.Rules = filteredRules

			results := engine.RunAudit(pol)

			hostname, _ := os.Hostname()
			osName := runtime.GOOS
			if osName == "linux" {
				osName = getLinuxDistro()
			}
			targetLabel := fmt.Sprintf("%s SERVER (%s)", strings.ToUpper(osName), hostname)

			filename, err := report.GenerateReport(results, targetLabel)

			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to generate PDF"})
				return
			}
			c.Header("Content-Disposition", "attachment; filename="+filename)
			c.Header("Content-Type", "application/pdf")
			c.File(filename)
		})

		// 6. MASTER RESET
		api.POST("/reset", func(c *gin.Context) {
			pol := loadCurrentPolicy()
			summary, _ := engine.RevertAll(pol)
			c.JSON(200, gin.H{
				"status":  "reset_complete",
				"message": summary,
			})
		})
	}

	fmt.Println("\n[UI] Dashboard available at http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

func loadCurrentPolicy() *policy.Policy {

	if runtime.GOOS == "windows" {
		pol, err := policy.LoadPolicy("policies/annexure_a.json")
		if err != nil {
			log.Printf("[ERROR] Failed to load policy: %v", err)
			return nil
		}
		return pol
	}

	distro := getLinuxDistro()
	if distro == "CentOS" {

		if _, err := os.Stat("policies/annexure_b.json"); err == nil {
			pol, err := policy.LoadPolicy("policies/annexure_b.json")
			if err != nil {
				log.Printf("[ERROR] Failed to load policy: %v", err)
				return nil
			}
			return pol
		}

		fmt.Println("[WARN] CentOS detected but 'annexure_b.json' missing. Using default.")
	}

	pol, err := policy.LoadPolicy("policies/annexure_b.json")
	if err != nil {
		log.Printf("[ERROR] Failed to load policy: %v", err)
		return nil
	}
	return pol
}

func getLinuxDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	content := strings.ToLower(string(data))

	if strings.Contains(content, "centos") {
		return "CentOS"
	}
	if strings.Contains(content, "ubuntu") {
		return "Ubuntu"
	}
	if strings.Contains(content, "rhel") || strings.Contains(content, "red hat") {
		return "RHEL"
	}
	if strings.Contains(content, "debian") {
		return "Debian"
	}

	return "Linux"
}
