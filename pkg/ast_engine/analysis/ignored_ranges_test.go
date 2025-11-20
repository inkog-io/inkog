package analysis

import (
	"testing"
)

func TestIgnoredRanges_NewIgnoredRanges(t *testing.T) {
	ir := NewIgnoredRanges()
	if ir == nil {
		t.Fatal("NewIgnoredRanges returned nil")
	}
	if ir.Count() != 0 {
		t.Errorf("expected Count() = 0, got %d", ir.Count())
	}
}

func TestIgnoredRanges_Add(t *testing.T) {
	ir := NewIgnoredRanges()

	ir.Add(0, 10, RangeTypeDocstring, "test docstring")
	if ir.Count() != 1 {
		t.Errorf("expected Count() = 1, got %d", ir.Count())
	}

	ir.Add(20, 30, RangeTypeComment, "test comment")
	if ir.Count() != 2 {
		t.Errorf("expected Count() = 2, got %d", ir.Count())
	}
}

func TestIgnoredRanges_Add_InvalidRange(t *testing.T) {
	ir := NewIgnoredRanges()

	// Add invalid range (startByte >= endByte)
	ir.Add(10, 10, RangeTypeDocstring, "invalid")
	if ir.Count() != 0 {
		t.Errorf("expected Count() = 0 for invalid range, got %d", ir.Count())
	}

	ir.Add(30, 20, RangeTypeDocstring, "invalid")
	if ir.Count() != 0 {
		t.Errorf("expected Count() = 0 for invalid range, got %d", ir.Count())
	}
}

func TestIgnoredRanges_IsBytePositionIgnored(t *testing.T) {
	ir := NewIgnoredRanges()
	ir.Add(10, 20, RangeTypeDocstring, "docstring")
	ir.Add(50, 60, RangeTypeComment, "comment")

	tests := []struct {
		name     string
		bytePos  int
		expected bool
	}{
		{"before first range", 5, false},
		{"start of first range", 10, true},
		{"middle of first range", 15, true},
		{"end-1 of first range", 19, true},
		{"end of first range", 20, false},
		{"between ranges", 30, false},
		{"start of second range", 50, true},
		{"middle of second range", 55, true},
		{"after second range", 70, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ir.IsBytePositionIgnored(tt.bytePos)
			if result != tt.expected {
				t.Errorf("IsBytePositionIgnored(%d) = %v, expected %v", tt.bytePos, result, tt.expected)
			}
		})
	}
}

func TestIgnoredRanges_FindRangeAt(t *testing.T) {
	ir := NewIgnoredRanges()
	ir.Add(10, 20, RangeTypeDocstring, "docstring range")
	ir.Add(50, 60, RangeTypeComment, "comment range")

	tests := []struct {
		name        string
		bytePos     int
		expectFound bool
		expectType  RangeType
		expectReason string
	}{
		{"inside docstring", 15, true, RangeTypeDocstring, "docstring range"},
		{"inside comment", 55, true, RangeTypeComment, "comment range"},
		{"not ignored", 30, false, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, found := ir.FindRangeAt(tt.bytePos)
			if found != tt.expectFound {
				t.Errorf("FindRangeAt(%d) found = %v, expected %v", tt.bytePos, found, tt.expectFound)
			}
			if found && tt.expectFound {
				if r.Type != tt.expectType {
					t.Errorf("expected Type = %s, got %s", tt.expectType, r.Type)
				}
				if r.Reason != tt.expectReason {
					t.Errorf("expected Reason = %s, got %s", tt.expectReason, r.Reason)
				}
			}
		})
	}
}

func TestIgnoredRanges_IsRangeIgnored(t *testing.T) {
	ir := NewIgnoredRanges()
	ir.Add(10, 20, RangeTypeDocstring, "docstring")
	ir.Add(50, 60, RangeTypeComment, "comment")

	tests := []struct {
		name     string
		startByte int
		endByte  int
		expected bool
	}{
		{"completely before", 0, 5, false},
		{"starts before, ends inside", 5, 15, true},
		{"completely inside", 12, 18, true},
		{"starts inside, ends after", 15, 25, true},
		{"completely overlaps", 5, 25, true},
		{"between ranges", 30, 40, false},
		{"in second range", 51, 59, true},
		{"starts at range end", 20, 25, false},
		{"ends at range start", 5, 10, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ir.IsRangeIgnored(tt.startByte, tt.endByte)
			if result != tt.expected {
				t.Errorf("IsRangeIgnored(%d, %d) = %v, expected %v", tt.startByte, tt.endByte, result, tt.expected)
			}
		})
	}
}

func TestIgnoredRanges_FilterOutIgnored(t *testing.T) {
	ir := NewIgnoredRanges()
	ir.Add(10, 20, RangeTypeDocstring, "docstring")
	ir.Add(50, 60, RangeTypeComment, "comment")

	positions := []int{5, 15, 25, 35, 55, 65}
	filtered := ir.FilterOutIgnored(positions)

	expected := []int{5, 25, 35, 65}

	if len(filtered) != len(expected) {
		t.Errorf("expected %d positions, got %d", len(expected), len(filtered))
		return
	}

	for i, pos := range filtered {
		if pos != expected[i] {
			t.Errorf("position %d: expected %d, got %d", i, expected[i], pos)
		}
	}
}

func TestIgnoredRanges_FilterOutIgnored_Empty(t *testing.T) {
	ir := NewIgnoredRanges()
	ir.Add(10, 20, RangeTypeDocstring, "docstring")

	// Empty slice
	filtered := ir.FilterOutIgnored([]int{})
	if len(filtered) != 0 {
		t.Errorf("expected empty result, got %d positions", len(filtered))
	}

	// Nil slice
	filtered = ir.FilterOutIgnored(nil)
	if len(filtered) != 0 {
		t.Errorf("expected empty result, got %d positions", len(filtered))
	}
}

func TestIgnoredRanges_GetRangesByType(t *testing.T) {
	ir := NewIgnoredRanges()
	ir.Add(10, 20, RangeTypeDocstring, "docstring 1")
	ir.Add(30, 40, RangeTypeComment, "comment 1")
	ir.Add(50, 60, RangeTypeDocstring, "docstring 2")
	ir.Add(70, 80, RangeTypeGeneratedCode, "generated")

	docstringRanges := ir.GetRangesByType(RangeTypeDocstring)
	if len(docstringRanges) != 2 {
		t.Errorf("expected 2 docstring ranges, got %d", len(docstringRanges))
	}

	commentRanges := ir.GetRangesByType(RangeTypeComment)
	if len(commentRanges) != 1 {
		t.Errorf("expected 1 comment range, got %d", len(commentRanges))
	}

	generatedRanges := ir.GetRangesByType(RangeTypeGeneratedCode)
	if len(generatedRanges) != 1 {
		t.Errorf("expected 1 generated code range, got %d", len(generatedRanges))
	}

	deadCodeRanges := ir.GetRangesByType(RangeTypeDeadCode)
	if len(deadCodeRanges) != 0 {
		t.Errorf("expected 0 dead code ranges, got %d", len(deadCodeRanges))
	}
}

func TestIgnoredRanges_Sorting(t *testing.T) {
	ir := NewIgnoredRanges()

	// Add ranges in non-sorted order
	ir.Add(50, 60, RangeTypeComment, "comment")
	ir.Add(10, 20, RangeTypeDocstring, "docstring")
	ir.Add(30, 40, RangeTypeDeadCode, "dead code")

	// After adding ranges, sorted flag should be false
	if ir.sorted {
		t.Error("expected sorted flag to be false after adding ranges")
	}

	// Calling IsBytePositionIgnored should trigger sorting
	_ = ir.IsBytePositionIgnored(15)

	// Now sorted flag should be true
	if !ir.sorted {
		t.Error("expected sorted flag to be true after first query")
	}

	// Verify ranges are correctly sorted and searchable
	tests := []struct {
		pos      int
		expected bool
	}{
		{15, true},  // in first range (10-20)
		{35, true},  // in second range (30-40)
		{55, true},  // in third range (50-60)
		{25, false}, // not in any range
	}

	for _, tt := range tests {
		result := ir.IsBytePositionIgnored(tt.pos)
		if result != tt.expected {
			t.Errorf("IsBytePositionIgnored(%d) = %v, expected %v", tt.pos, result, tt.expected)
		}
	}
}

func TestIgnoredRanges_Count(t *testing.T) {
	ir := NewIgnoredRanges()
	if ir.Count() != 0 {
		t.Errorf("expected initial count 0, got %d", ir.Count())
	}

	ir.Add(0, 10, RangeTypeDocstring, "docstring")
	if ir.Count() != 1 {
		t.Errorf("expected count 1, got %d", ir.Count())
	}

	ir.Add(20, 30, RangeTypeComment, "comment")
	if ir.Count() != 2 {
		t.Errorf("expected count 2, got %d", ir.Count())
	}

	ir.Add(40, 50, RangeTypeDeadCode, "dead code")
	if ir.Count() != 3 {
		t.Errorf("expected count 3, got %d", ir.Count())
	}
}

func TestIgnoredRanges_RangeTypes(t *testing.T) {
	tests := []struct {
		rangeType RangeType
		expected  string
	}{
		{RangeTypeDocstring, "docstring"},
		{RangeTypeComment, "comment"},
		{RangeTypeDeadCode, "dead_code"},
		{RangeTypeGeneratedCode, "generated_code"},
	}

	for _, tt := range tests {
		if string(tt.rangeType) != tt.expected {
			t.Errorf("RangeType string value = %s, expected %s", tt.rangeType, tt.expected)
		}
	}
}

func BenchmarkIgnoredRanges_Add(b *testing.B) {
	ir := NewIgnoredRanges()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ir.Add(i*10, i*10+10, RangeTypeDocstring, "benchmark")
	}
}

func BenchmarkIgnoredRanges_IsBytePositionIgnored(b *testing.B) {
	ir := NewIgnoredRanges()
	for i := 0; i < 1000; i++ {
		ir.Add(i*100, i*100+50, RangeTypeDocstring, "benchmark")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ir.IsBytePositionIgnored(50000 + (i % 100))
	}
}

func BenchmarkIgnoredRanges_FilterOutIgnored(b *testing.B) {
	ir := NewIgnoredRanges()
	for i := 0; i < 100; i++ {
		ir.Add(i*1000, i*1000+500, RangeTypeDocstring, "benchmark")
	}

	positions := make([]int, 0, 1000)
	for i := 0; i < 1000; i++ {
		positions = append(positions, i*100)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ir.FilterOutIgnored(positions)
	}
}
