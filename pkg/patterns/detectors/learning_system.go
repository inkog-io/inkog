package detectors

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/inkog-io/inkog/action/pkg/patterns"
)

// LearningSystem manages persistent feedback collection and recalibration
// Stores predictions and actual results for continuous improvement
type LearningSystem struct {
	storageDir string
	predictions *PredictionLog
	actuals *ActualResultLog
	metrics *MetricsCalculator
	mutex  sync.RWMutex
}

// PredictionLog stores detection predictions
type PredictionLog struct {
	Predictions []PredictionEntry
	filePath   string
	mutex      sync.Mutex
}

// PredictionEntry represents one detection prediction
type PredictionEntry struct {
	ID               string            // Unique ID for this prediction
	PatternID        string            // Pattern that made the detection
	FindingCode      string            // The code that triggered detection
	PredictedConf    float32           // Predicted confidence score
	FilteredByGuard  bool              // Whether guard framework filtered it
	FactorScores     map[string]float32 // Individual factor scores
	SemanticRisk     float32           // AI-assessed semantic risk
	FalsePositiveLik float32           // AI-assessed FP likelihood
	Timestamp        time.Time         // When prediction was made
}

// ActualResultLog stores verified results
type ActualResultLog struct {
	Results []ActualResultEntry
	filePath string
	mutex    sync.Mutex
}

// ActualResultEntry represents verified detection accuracy
type ActualResultEntry struct {
	PredictionID   string    // Links to prediction
	PatternID      string    // Pattern that made the detection
	IsTruePositive bool      // Was it actually a vulnerability?
	ActualSeverity string    // Actual risk level
	VerificationMethod string // How was it verified? (manual, test, etc)
	Timestamp      time.Time // When verified
	Notes          string    // Additional context
}

// MetricsCalculator computes accuracy statistics
type MetricsCalculator struct {
	metrics *AccuracyMetrics
	mutex   sync.RWMutex
}

// AccuracyMetrics tracks detection performance
type AccuracyMetrics struct {
	TotalPredictions  int
	TruePositives     int
	FalsePositives    int
	TrueNegatives     int
	FalseNegatives    int
	Accuracy          float32 // (TP+TN) / (TP+TN+FP+FN)
	Precision         float32 // TP / (TP+FP)
	Recall            float32 // TP / (TP+FN)
	F1Score           float32 // 2 * (Precision * Recall) / (Precision + Recall)
	ConfidenceError   float32 // Average error in confidence scores
	PerPatternMetrics map[string]*PatternMetrics
	LastUpdated       time.Time
}

// PatternMetrics tracks per-pattern performance
type PatternMetrics struct {
	PatternID      string
	Predictions    int
	Accuracy       float32
	FalsePositives int
	FalsePositiveRate float32
	AvgConfidence  float32
	ConfidenceError float32
}

// LearningRecalibrationGuidance provides recommendations for weight adjustments
type LearningRecalibrationGuidance struct {
	OverallAccuracy    float32
	RecommendedChanges map[string]LearningWeightAdjustment
	HighestFPPatterns  []string
	LowestAccPatterns  []string
	Confidence         float32 // How confident in these recommendations
}

// LearningWeightAdjustment specifies how to adjust a factor weight
type LearningWeightAdjustment struct {
	FactorName        string
	CurrentWeight     float32
	RecommendedWeight float32
	Reasoning         string
	Impact            string
}

// NewLearningSystem creates a new learning system
func NewLearningSystem(storageDir string) (*LearningSystem, error) {
	// Ensure storage directory exists
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	ls := &LearningSystem{
		storageDir: storageDir,
		predictions: &PredictionLog{
			Predictions: []PredictionEntry{},
			filePath:   filepath.Join(storageDir, "predictions.jsonl"),
		},
		actuals: &ActualResultLog{
			Results: []ActualResultEntry{},
			filePath: filepath.Join(storageDir, "actuals.jsonl"),
		},
		metrics: &MetricsCalculator{
			metrics: &AccuracyMetrics{
				PerPatternMetrics: make(map[string]*PatternMetrics),
			},
		},
	}

	// Load existing data
	if err := ls.Load(); err != nil {
		// If files don't exist yet, that's OK
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load existing data: %w", err)
		}
	}

	return ls, nil
}

// RecordPrediction stores a detection prediction
func (ls *LearningSystem) RecordPrediction(
	patternID string,
	finding *patterns.Finding,
	confidence float32,
	filtered bool,
	factorScores map[string]float32,
	semanticAssessment *SemanticAssessment,
) string {
	ls.mutex.Lock()
	defer ls.mutex.Unlock()

	id := fmt.Sprintf("%s_%d", patternID, time.Now().UnixNano())

	prediction := PredictionEntry{
		ID:              id,
		PatternID:       patternID,
		FindingCode:     finding.Code,
		PredictedConf:   confidence,
		FilteredByGuard: filtered,
		FactorScores:    factorScores,
		Timestamp:       time.Now(),
	}

	if semanticAssessment != nil {
		prediction.SemanticRisk = semanticAssessment.VulnerabilityRisk
		prediction.FalsePositiveLik = semanticAssessment.FalsePositiveLikelihood
	}

	ls.predictions.Predictions = append(ls.predictions.Predictions, prediction)
	ls.savePredictions()

	return id
}

// RecordActualResult records the verified result of a prediction
func (ls *LearningSystem) RecordActualResult(
	predictionID string,
	patternID string,
	isTruePositive bool,
	actualSeverity string,
	method string,
	notes string,
) error {
	ls.mutex.Lock()
	defer ls.mutex.Unlock()

	result := ActualResultEntry{
		PredictionID:       predictionID,
		PatternID:          patternID,
		IsTruePositive:     isTruePositive,
		ActualSeverity:     actualSeverity,
		VerificationMethod: method,
		Timestamp:          time.Now(),
		Notes:              notes,
	}

	ls.actuals.Results = append(ls.actuals.Results, result)
	ls.saveActuals()

	// Recalculate metrics
	ls.metrics.Calculate(ls.predictions.Predictions, ls.actuals.Results)

	return nil
}

// GetMetrics returns current accuracy metrics
func (ls *LearningSystem) GetMetrics() *AccuracyMetrics {
	ls.mutex.RLock()
	defer ls.mutex.RUnlock()

	return ls.metrics.metrics
}

// GenerateRecalibrationGuidance creates recommendations for weight adjustments
func (ls *LearningSystem) GenerateRecalibrationGuidance() *LearningRecalibrationGuidance {
	ls.mutex.RLock()
	defer ls.mutex.RUnlock()

	guidance := &LearningRecalibrationGuidance{
		OverallAccuracy:    ls.metrics.metrics.Accuracy,
		RecommendedChanges: make(map[string]LearningWeightAdjustment),
		Confidence:         0.8,
	}

	// If we have enough data, generate recommendations
	if ls.metrics.metrics.TotalPredictions < 10 {
		guidance.Confidence = 0.3 // Not enough data for confident recommendations
		return guidance
	}

	// Analyze which patterns have high false positive rates
	for patternID, patMetrics := range ls.metrics.metrics.PerPatternMetrics {
		if patMetrics.FalsePositiveRate > 0.3 {
			guidance.HighestFPPatterns = append(guidance.HighestFPPatterns, patternID)

			// Recommend reducing aggressiveness for this pattern
			guidance.RecommendedChanges[patternID+"_data_flow"] = LearningWeightAdjustment{
				FactorName:        "data_flow_risk",
				CurrentWeight:     0.20,
				RecommendedWeight: 0.15,
				Reasoning:         fmt.Sprintf("High FP rate (%.1f%%) in %s", patMetrics.FalsePositiveRate*100, patternID),
				Impact:            "More conservative detection for this pattern",
			}
		}

		if patMetrics.Accuracy < 0.7 {
			guidance.LowestAccPatterns = append(guidance.LowestAccPatterns, patternID)
		}
	}

	return guidance
}

// GetPatternMetrics returns metrics for a specific pattern
func (ls *LearningSystem) GetPatternMetrics(patternID string) *PatternMetrics {
	ls.mutex.RLock()
	defer ls.mutex.RUnlock()

	if metrics, ok := ls.metrics.metrics.PerPatternMetrics[patternID]; ok {
		return metrics
	}
	return nil
}

// Save persists all data to disk
func (ls *LearningSystem) Save() error {
	ls.mutex.Lock()
	defer ls.mutex.Unlock()

	if err := ls.savePredictions(); err != nil {
		return err
	}

	if err := ls.saveActuals(); err != nil {
		return err
	}

	return ls.saveMetrics()
}

// Load loads all data from disk
func (ls *LearningSystem) Load() error {
	ls.mutex.Lock()
	defer ls.mutex.Unlock()

	if err := ls.loadPredictions(); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := ls.loadActuals(); err != nil && !os.IsNotExist(err) {
		return err
	}

	// Recalculate metrics
	ls.metrics.Calculate(ls.predictions.Predictions, ls.actuals.Results)

	return nil
}

// Helper methods

func (ls *LearningSystem) savePredictions() error {
	file, err := os.Create(ls.predictions.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, pred := range ls.predictions.Predictions {
		data, err := json.Marshal(pred)
		if err != nil {
			return err
		}
		if _, err := file.WriteString(string(data) + "\n"); err != nil {
			return err
		}
	}

	return nil
}

func (ls *LearningSystem) loadPredictions() error {
	file, err := os.Open(ls.predictions.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var pred PredictionEntry
		if err := json.Unmarshal(scanner.Bytes(), &pred); err != nil {
			continue // Skip malformed lines
		}
		ls.predictions.Predictions = append(ls.predictions.Predictions, pred)
	}

	return scanner.Err()
}

func (ls *LearningSystem) saveActuals() error {
	file, err := os.Create(ls.actuals.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, result := range ls.actuals.Results {
		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err := file.WriteString(string(data) + "\n"); err != nil {
			return err
		}
	}

	return nil
}

func (ls *LearningSystem) loadActuals() error {
	file, err := os.Open(ls.actuals.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var result ActualResultEntry
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			continue // Skip malformed lines
		}
		ls.actuals.Results = append(ls.actuals.Results, result)
	}

	return scanner.Err()
}

func (ls *LearningSystem) saveMetrics() error {
	metricsPath := filepath.Join(ls.storageDir, "metrics.json")
	data, err := json.MarshalIndent(ls.metrics.metrics, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(metricsPath, data, 0644)
}

// Calculate computes metrics from predictions and actuals
func (mc *MetricsCalculator) Calculate(predictions []PredictionEntry, actuals []ActualResultEntry) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.metrics = &AccuracyMetrics{
		PerPatternMetrics: make(map[string]*PatternMetrics),
		LastUpdated:       time.Now(),
	}

	if len(actuals) == 0 {
		mc.metrics.Accuracy = 1.0 // No data, assume perfect (will update with actual data)
		return
	}

	// Build map of prediction IDs to predictions for quick lookup
	predMap := make(map[string]PredictionEntry)
	for _, pred := range predictions {
		predMap[pred.ID] = pred
	}

	// Process each actual result
	patternStats := make(map[string]*PatternMetrics)

	for _, actual := range actuals {
		mc.metrics.TotalPredictions++

		// Get corresponding prediction
		pred, ok := predMap[actual.PredictionID]
		if !ok {
			continue
		}

		// Initialize pattern metrics if needed
		if _, ok := patternStats[actual.PatternID]; !ok {
			patternStats[actual.PatternID] = &PatternMetrics{
				PatternID: actual.PatternID,
			}
		}

		pm := patternStats[actual.PatternID]
		pm.Predictions++
		pm.AvgConfidence += pred.PredictedConf

		// Count true/false positives/negatives
		if actual.IsTruePositive {
			mc.metrics.TruePositives++
		} else {
			mc.metrics.FalsePositives++
			pm.FalsePositives++
		}
	}

	// Calculate aggregated metrics
	if mc.metrics.TotalPredictions > 0 {
		mc.metrics.Accuracy = float32(mc.metrics.TruePositives) / float32(mc.metrics.TotalPredictions)

		if mc.metrics.TruePositives+mc.metrics.FalsePositives > 0 {
			mc.metrics.Precision = float32(mc.metrics.TruePositives) / float32(mc.metrics.TruePositives+mc.metrics.FalsePositives)
		}

		if mc.metrics.TruePositives+mc.metrics.FalseNegatives > 0 {
			mc.metrics.Recall = float32(mc.metrics.TruePositives) / float32(mc.metrics.TruePositives+mc.metrics.FalseNegatives)
		}

		if mc.metrics.Precision+mc.metrics.Recall > 0 {
			mc.metrics.F1Score = 2 * (mc.metrics.Precision * mc.metrics.Recall) / (mc.metrics.Precision + mc.metrics.Recall)
		}
	}

	// Calculate per-pattern metrics
	for _, pm := range patternStats {
		if pm.Predictions > 0 {
			pm.Accuracy = float32(pm.Predictions-pm.FalsePositives) / float32(pm.Predictions)
			pm.FalsePositiveRate = float32(pm.FalsePositives) / float32(pm.Predictions)
			pm.AvgConfidence = pm.AvgConfidence / float32(pm.Predictions)
		}
		mc.metrics.PerPatternMetrics[pm.PatternID] = pm
	}
}
