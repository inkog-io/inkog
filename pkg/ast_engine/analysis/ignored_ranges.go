package analysis

import (
	"sort"
)

// RangeType represents the category of an ignored range
type RangeType string

const (
	RangeTypeDocstring    RangeType = "docstring"
	RangeTypeComment      RangeType = "comment"
	RangeTypeDeadCode     RangeType = "dead_code"
	RangeTypeGeneratedCode RangeType = "generated_code"
)

// IgnoredRange represents a byte range in source code that should be skipped by detectors
type IgnoredRange struct {
	StartByte int       // Inclusive start byte position
	EndByte   int       // Exclusive end byte position
	Type      RangeType // Reason for ignoring this range
	Reason    string    // Human-readable explanation
}

// IgnoredRanges is a collection of ranges that should be skipped during analysis
type IgnoredRanges struct {
	ranges []IgnoredRange
	// sorted flag tracks whether ranges are sorted by StartByte
	sorted bool
}

// NewIgnoredRanges creates an empty IgnoredRanges collection
func NewIgnoredRanges() *IgnoredRanges {
	return &IgnoredRanges{
		ranges: make([]IgnoredRange, 0),
		sorted: true,
	}
}

// Add inserts a new ignored range into the collection
func (ir *IgnoredRanges) Add(startByte, endByte int, rangeType RangeType, reason string) {
	if startByte >= endByte {
		return // Invalid range, ignore
	}
	ir.ranges = append(ir.ranges, IgnoredRange{
		StartByte: startByte,
		EndByte:   endByte,
		Type:      rangeType,
		Reason:    reason,
	})
	ir.sorted = false // Mark as unsorted since we added a new range
}

// IsBytePositionIgnored checks if a given byte position is within any ignored range
func (ir *IgnoredRanges) IsBytePositionIgnored(bytePos int) bool {
	_, found := ir.FindRangeAt(bytePos)
	return found
}

// FindRangeAt returns the IgnoredRange at the given byte position, if any
func (ir *IgnoredRanges) FindRangeAt(bytePos int) (*IgnoredRange, bool) {
	// Ensure ranges are sorted for binary search
	if !ir.sorted {
		ir.sortRanges()
	}

	for i := range ir.ranges {
		r := &ir.ranges[i]
		if bytePos >= r.StartByte && bytePos < r.EndByte {
			return r, true
		}
	}
	return nil, false
}

// IsRangeIgnored checks if a given byte range overlaps with any ignored ranges
func (ir *IgnoredRanges) IsRangeIgnored(startByte, endByte int) bool {
	if startByte >= endByte {
		return false
	}

	// Ensure ranges are sorted
	if !ir.sorted {
		ir.sortRanges()
	}

	for i := range ir.ranges {
		r := &ir.ranges[i]
		// Check for overlap: ranges overlap if one starts before the other ends
		if startByte < r.EndByte && endByte > r.StartByte {
			return true
		}
	}
	return false
}

// FilterOutIgnored removes findings that fall within ignored ranges
func (ir *IgnoredRanges) FilterOutIgnored(bytePositions []int) []int {
	if len(bytePositions) == 0 {
		return bytePositions
	}

	result := make([]int, 0, len(bytePositions))
	for _, pos := range bytePositions {
		if !ir.IsBytePositionIgnored(pos) {
			result = append(result, pos)
		}
	}
	return result
}

// GetRangesByType returns all ignored ranges of a specific type
func (ir *IgnoredRanges) GetRangesByType(rangeType RangeType) []IgnoredRange {
	result := make([]IgnoredRange, 0)
	for i := range ir.ranges {
		if ir.ranges[i].Type == rangeType {
			result = append(result, ir.ranges[i])
		}
	}
	return result
}

// Count returns the number of ignored ranges
func (ir *IgnoredRanges) Count() int {
	return len(ir.ranges)
}

// sortRanges sorts the ranges by StartByte for efficient searching
func (ir *IgnoredRanges) sortRanges() {
	sort.Slice(ir.ranges, func(i, j int) bool {
		return ir.ranges[i].StartByte < ir.ranges[j].StartByte
	})
	ir.sorted = true
}
