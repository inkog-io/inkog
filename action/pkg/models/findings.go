package models

import (
	"encoding/json"
	"time"
)

// RiskLevel represents the severity of a finding
type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

// Finding represents a single security finding
type Finding struct {
	ID              string    `json:"id"`
	Pattern         string    `json:"pattern"`
	Severity        RiskLevel `json:"severity"`
	Confidence      float64   `json:"confidence"` // 0.0-1.0
	File            string    `json:"file"`
	Line            int       `json:"line"`
	Column          int       `json:"column"`
	Message         string    `json:"message"`
	Code            string    `json:"code_snippet"`
	Remediation     string    `json:"remediation"`
	ReferenceLinks  []string  `json:"reference_links,omitempty"`
	CWEIdentifiers  []string  `json:"cwe_identifiers,omitempty"`
	DetectionMethod string    `json:"detection_method"`
}

// ScanResult represents the complete scan result
type ScanResult struct {
	Timestamp      time.Time   `json:"timestamp"`
	Framework      string      `json:"framework"`
	RiskScore      int         `json:"risk_score"` // 0-100
	FindingsCount  int         `json:"findings_count"`
	HighRiskCount  int         `json:"high_risk_count"`
	MediumRiskCount int        `json:"medium_risk_count"`
	LowRiskCount   int         `json:"low_risk_count"`
	Findings       []Finding   `json:"findings"`
	ScanDuration   string      `json:"scan_duration"`
	FilesScanned   int         `json:"files_scanned"`
	LinesOfCode    int         `json:"lines_of_code"`
}

// SeverityScore returns the numeric score for a risk level
func (r RiskLevel) Score() int {
	switch r {
	case RiskLevelHigh:
		return 3
	case RiskLevelMedium:
		return 2
	case RiskLevelLow:
		return 1
	default:
		return 0
	}
}

// CalculateRiskScore calculates the overall risk score (0-100)
func CalculateRiskScore(findings []Finding) int {
	if len(findings) == 0 {
		return 0
	}

	totalScore := 0
	for _, f := range findings {
		severity := RiskLevel(f.Severity).Score()
		confidence := int(f.Confidence * 100)
		totalScore += (severity * 10) * (confidence / 100)
	}

	// Normalize to 0-100 scale
	maxScore := len(findings) * 30 // max 3 * 10 * 100
	score := (totalScore * 100) / maxScore
	if score > 100 {
		return 100
	}
	return score
}

// MarshalJSON implements custom JSON marshaling
func (r *ScanResult) MarshalJSON() ([]byte, error) {
	type Alias ScanResult
	return json.MarshalIndent(&struct {
		*Alias
	}{
		Alias: (*Alias)(r),
	}, "", "  ")
}
