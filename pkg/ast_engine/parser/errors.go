package parser

import "fmt"

// Error types for the parser
var (
	ErrParserNotInitialized = fmt.Errorf("parser not initialized")
	ErrLanguageNotSupported = fmt.Errorf("language not supported")
	ErrInvalidQuery         = fmt.Errorf("invalid query syntax")
	ErrParseFailure         = fmt.Errorf("parse failure")
	ErrFileTooLarge         = fmt.Errorf("file too large")
	ErrParseTimeout         = fmt.Errorf("parse timeout")
	ErrSymbolTableBuild     = fmt.Errorf("failed to build symbol table")
	ErrNilNode              = fmt.Errorf("node is nil")
	ErrInvalidNodeType      = fmt.Errorf("invalid node type")
)

// ParseError represents a detailed parse error
type ParseError struct {
	Message  string
	FilePath string
	Line     int
	Column   int
	Code     string
}

// Error implements the error interface
func (pe *ParseError) Error() string {
	return fmt.Sprintf("%s at %s:%d:%d: %s", pe.Message, pe.FilePath, pe.Line, pe.Column, pe.Code)
}

// NewParseError creates a new parse error
func NewParseError(message, filePath string, line, column int, code string) *ParseError {
	return &ParseError{
		Message:  message,
		FilePath: filePath,
		Line:     line,
		Column:   column,
		Code:     code,
	}
}
