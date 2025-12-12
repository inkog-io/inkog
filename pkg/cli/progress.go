package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/briandowns/spinner"
)

// ProgressReporter manages CLI progress indicators (spinners)
// When quiet mode is enabled, all output is suppressed for CI/CD compatibility
type ProgressReporter struct {
	spinner *spinner.Spinner
	quiet   bool
	active  bool
}

// NewProgressReporter creates a new progress reporter
// Set quiet=true to disable all spinners (for JSON output or CI environments)
func NewProgressReporter(quiet bool) *ProgressReporter {
	pr := &ProgressReporter{
		quiet:  quiet,
		active: false,
	}

	if !quiet {
		// Use a clean spinner style (dots)
		pr.spinner = spinner.New(spinner.CharSets[14], 100*time.Millisecond)
		pr.spinner.Writer = os.Stderr // Write to stderr to keep stdout clean
	}

	return pr
}

// Start begins showing a spinner with the given message
func (p *ProgressReporter) Start(message string) {
	if p.quiet || p.spinner == nil {
		return
	}

	p.spinner.Suffix = " " + message
	p.spinner.Start()
	p.active = true
}

// Update changes the spinner message without stopping it
func (p *ProgressReporter) Update(message string) {
	if p.quiet || p.spinner == nil {
		return
	}

	p.spinner.Suffix = " " + message
}

// Success stops the spinner and displays a success message
func (p *ProgressReporter) Success(message string) {
	if p.quiet {
		return
	}

	if p.spinner != nil && p.active {
		p.spinner.Stop()
		p.active = false
	}

	fmt.Fprintf(os.Stderr, "\r✓ %s\n", message)
}

// Fail stops the spinner and displays an error message
func (p *ProgressReporter) Fail(message string) {
	if p.quiet {
		return
	}

	if p.spinner != nil && p.active {
		p.spinner.Stop()
		p.active = false
	}

	fmt.Fprintf(os.Stderr, "\r✗ %s\n", message)
}

// Stop stops the spinner silently without a message
func (p *ProgressReporter) Stop() {
	if p.spinner != nil && p.active {
		p.spinner.Stop()
		p.active = false
	}
}

// Info prints an informational message (respects quiet mode)
func (p *ProgressReporter) Info(message string) {
	if p.quiet {
		return
	}

	// Temporarily stop spinner if active
	wasActive := p.active
	if wasActive && p.spinner != nil {
		p.spinner.Stop()
	}

	fmt.Fprintf(os.Stderr, "  %s\n", message)

	// Restart spinner if it was active
	if wasActive && p.spinner != nil {
		p.spinner.Start()
	}
}

// IsQuiet returns whether quiet mode is enabled
func (p *ProgressReporter) IsQuiet() bool {
	return p.quiet
}
