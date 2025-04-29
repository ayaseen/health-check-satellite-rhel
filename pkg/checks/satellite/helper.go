// pkg/checks/satellite/helper.go

package satellite

import (
	"strings"
)

// FormatDetailSection formats a section of detail text with proper AsciiDoc-compatible formatting
// title: the section title
// content: the content to format (usually command output)
// This ensures proper rendering in the AsciiDoc report
func FormatDetailSection(title string, content string) string {
	var sb strings.Builder
	sb.WriteString(title + ":\n")

	// Handle empty content
	if content == "" {
		sb.WriteString("No information available\n\n")
		return sb.String()
	}

	// If the content contains table-like structures or special formatting,
	// wrap it in a code block to prevent AsciiDoc interpretation issues
	if containsTableStructure(content) ||
		containsSpecialFormatting(content) ||
		containsCommandOutput(content) {
		sb.WriteString("[source,text]\n----\n")
		sb.WriteString(content)
		if !strings.HasSuffix(content, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("----\n\n")
	} else {
		// Regular content
		sb.WriteString(content)
		if !strings.HasSuffix(content, "\n") {
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// containsTableStructure checks if content contains table-like structures
// that would need special handling in AsciiDoc
func containsTableStructure(content string) bool {
	lines := strings.Split(content, "\n")
	pipeCount := 0

	// Check for multiple pipe characters that might indicate a table
	for _, line := range lines {
		if strings.Count(line, "|") > 1 {
			pipeCount++
		}
		// Look for typical table header/separator patterns
		if strings.Contains(line, "----") ||
			strings.Contains(line, "====") ||
			strings.Contains(line, "____") {
			return true
		}
	}

	// If multiple lines have multiple pipes, likely a table
	return pipeCount > 1
}

// containsSpecialFormatting checks if content contains special formatting
// that would need to be escaped in AsciiDoc
func containsSpecialFormatting(content string) bool {
	// Check for special AsciiDoc formatting characters
	return strings.Contains(content, "*") ||
		strings.Contains(content, "_") ||
		strings.Contains(content, "++") ||
		strings.Contains(content, "##") ||
		strings.Contains(content, "==") ||
		strings.Contains(content, "--") ||
		strings.Contains(content, "//") ||
		strings.Contains(content, "::")
}

// containsCommandOutput checks if content looks like command output
// that should be preserved as-is
func containsCommandOutput(content string) bool {
	// Check for common patterns in command output
	return strings.Contains(content, "$ ") ||
		strings.Contains(content, "# ") ||
		strings.Contains(content, "systemctl") ||
		strings.Contains(content, "rpm ") ||
		strings.Contains(content, "yum ") ||
		strings.Contains(content, "dnf ") ||
		strings.Contains(content, "Error:") ||
		strings.Contains(content, "Warning:") ||
		strings.Contains(content, "SUCCESS") ||
		strings.Contains(content, "FAILURE")
}

// BuildDetailString creates a complete detail string with multiple sections
// sections: a map of section titles to their content
// This ensures consistent formatting across all check functions
func BuildDetailString(sections map[string]string) string {
	var sb strings.Builder

	// Add a header if provided
	if header, ok := sections["header"]; ok {
		sb.WriteString(header)
		if !strings.HasSuffix(header, "\n\n") {
			if strings.HasSuffix(header, "\n") {
				sb.WriteString("\n")
			} else {
				sb.WriteString("\n\n")
			}
		}
		delete(sections, "header")
	}

	// Add remaining sections in the order provided
	for title, content := range sections {
		sb.WriteString(FormatDetailSection(title, content))
	}

	return sb.String()
}
