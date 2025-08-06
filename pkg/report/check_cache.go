// pkg/report/check_cache.go
// This file provides a caching mechanism for check results

package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// CheckCache provides thread-safe caching of check results
type CheckCache struct {
	mu    sync.RWMutex
	cache map[string]*AsciiDocReport
}

var (
	globalCheckCache = &CheckCache{
		cache: make(map[string]*AsciiDocReport),
	}
)

// CacheHostReport stores a host report in the cache
func CacheHostReport(hostname string, report *AsciiDocReport) {
	globalCheckCache.mu.Lock()
	defer globalCheckCache.mu.Unlock()
	globalCheckCache.cache[hostname] = report
}

// GetCachedHostReport retrieves a host report from the cache
func GetCachedHostReport(hostname string) (*AsciiDocReport, bool) {
	globalCheckCache.mu.RLock()
	defer globalCheckCache.mu.RUnlock()
	report, exists := globalCheckCache.cache[hostname]
	return report, exists
}

// ClearCache clears all cached reports
func ClearCache() {
	globalCheckCache.mu.Lock()
	defer globalCheckCache.mu.Unlock()
	globalCheckCache.cache = make(map[string]*AsciiDocReport)
}

// CheckResultData represents the structured check results for JSON storage
type CheckResultData struct {
	Hostname string      `json:"hostname"`
	Title    string      `json:"title"`
	Checks   []CheckData `json:"checks"`
}

type CheckData struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Category        string   `json:"category"`
	ResultKey       string   `json:"result_key"`
	Status          string   `json:"status"`
	Message         string   `json:"message"`
	Recommendations []string `json:"recommendations,omitempty"`
}

// SaveCheckResults saves check results to a JSON file
func SaveCheckResults(outputPath string, report *AsciiDocReport) error {
	// Create JSON filename in a .data subdirectory
	dir := filepath.Dir(outputPath)
	dataDir := filepath.Join(dir, ".data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	jsonFile := filepath.Join(dataDir, filepath.Base(outputPath)+".json")

	// Convert report to structured data
	data := CheckResultData{
		Hostname: report.Hostname,
		Title:    report.Title,
		Checks:   make([]CheckData, len(report.Checks)),
	}

	for i, check := range report.Checks {
		data.Checks[i] = CheckData{
			ID:              check.ID,
			Name:            check.Name,
			Category:        string(check.Category),
			ResultKey:       string(check.Result.ResultKey),
			Status:          string(check.Result.Status),
			Message:         check.Result.Message,
			Recommendations: check.Result.Recommendations,
		}
	}

	// Write JSON file
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal check results: %v", err)
	}

	if err := os.WriteFile(jsonFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write check results: %v", err)
	}

	return nil
}

// LoadCheckResults loads check results from a JSON file
func LoadCheckResults(outputPath string) (*AsciiDocReport, error) {
	// Look for JSON file in .data subdirectory
	dir := filepath.Dir(outputPath)
	jsonFile := filepath.Join(dir, ".data", filepath.Base(outputPath)+".json")

	jsonData, err := os.ReadFile(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read check results: %v", err)
	}

	var data CheckResultData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal check results: %v", err)
	}

	// Reconstruct AsciiDocReport
	report := &AsciiDocReport{
		OutputPath: outputPath,
		Hostname:   data.Hostname,
		Title:      data.Title,
		Checks:     make([]*Check, len(data.Checks)),
	}

	for i, checkData := range data.Checks {
		report.Checks[i] = &Check{
			ID:       checkData.ID,
			Name:     checkData.Name,
			Category: Category(checkData.Category),
			Result: Result{
				ResultKey:       ResultKey(checkData.ResultKey),
				Status:          Status(checkData.Status),
				Message:         checkData.Message,
				Recommendations: checkData.Recommendations,
			},
		}
	}

	return report, nil
}
