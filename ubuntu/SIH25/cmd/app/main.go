package main

import (
    "fmt"
    "log"
    "os"      // <--- ADDED for Hostname
    "runtime"
    "strings" // <--- ADDED for ToUpper
    "sih2025/internal/engine"
    "sih2025/internal/policy"
    "sih2025/internal/state"
    "sih2025/internal/report" 

    "github.com/gin-gonic/gin"
    _ "modernc.org/sqlite"
)

func main() {
    fmt.Println("==================================================")
    fmt.Printf("   SIH 2025 HARDENING ORCHESTRATOR (v1.0)\n")
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
        api.GET("/status", func(c *gin.Context) {
            c.JSON(200, gin.H{"status": "online", "os": runtime.GOOS})
        })

        // 1. SCAN
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

        // 2. FIX
        api.POST("/fix", func(c *gin.Context) {
            var req struct { ID string `json:"id"` }
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

        // 3. ROLLBACK
        api.POST("/rollback", func(c *gin.Context) {
            var req struct { ID string `json:"id"` }
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

        // 4. EXPORT REPORT (FIXED)
        api.GET("/export", func(c *gin.Context) {
            // A. Get Profile
            profile := c.DefaultQuery("level", "strict")
            pol := loadCurrentPolicy()
            
            // B. Apply Filter
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

            // C. Run Audit
            results := engine.RunAudit(pol)
            
            // D. Get System Info (NEW CODE)
            hostname, _ := os.Hostname()
            osName := strings.ToUpper(runtime.GOOS)
            targetLabel := fmt.Sprintf("%s SERVER (%s)", osName, hostname)

            // E. Generate PDF (PASSING 2 ARGUMENTS NOW)
            filename, err := report.GenerateReport(results, targetLabel)
            
            if err != nil {
                c.JSON(500, gin.H{"error": "Failed to generate PDF"})
                return
            }
            c.Header("Content-Disposition", "attachment; filename="+filename)
            c.Header("Content-Type", "application/pdf")
            c.File(filename)
        })

        // 5. MASTER RESET
        api.POST("/reset", func(c *gin.Context) {
            pol := loadCurrentPolicy()
            summary, _ := engine.RevertAll(pol)
            c.JSON(200, gin.H{
                "status": "reset_complete", 
                "message": summary,
            })
        })
    }

    fmt.Println("\n[UI] Dashboard available at http://localhost:8080")
    if err := r.Run(":8080"); err != nil {
        log.Fatal(err)
    }
}

// Helper
func loadCurrentPolicy() *policy.Policy {
    file := "policies/annexure_a.json"
    if runtime.GOOS == "linux" {
        file = "policies/annexure_b.json"
    }
    p, err := policy.LoadPolicy(file)
    if err != nil {
        return nil
    }
    return p
}