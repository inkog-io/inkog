# Inkog Interactive Demo

A powerful, interactive demonstration showcasing Inkog's multi-pattern AI agent security scanning capabilities through real malicious code examples.

## Overview

The demo presents a professional, dark-themed interface that demonstrates how Inkog simultaneously scans for 5 different security patterns and detects complete attack chains in AI agent code.

## Key Features

### 1. Multi-Pattern Detection Badge
- **Visual Indicator**: Header badge showing "Scanning 5 Patterns"
- **Expandable Tooltip**: Hover to see all active security patterns:
  - Hardcoded Credentials (CWE-798)
  - Prompt Injection (CWE-94)
  - Infinite Loops (CWE-835)
  - Unsafe Environment Access (CWE-665)
  - Remote Code Execution (CWE-78)

### 2. Real Attack Scenarios

#### Tab 1: Compromised Payment Agent (LangChain)
A production payment processing agent demonstrating:
- **3 Hardcoded Credentials**: OpenAI API key, Stripe live key, database password
- **Prompt Injection**: User input directly in payment requests
- **Data Exfiltration**: Stripe API key sent to attacker-controlled server
- **Infinite Loop**: Payment retry without break condition
- **Unsafe Environment Access**: Production database URL without defaults

**WOW Factor**: Shows credential compromise leading to payment fraud and data exfiltration

#### Tab 2: Supply Chain Risk Agent (CrewAI)
A data processing agent with critical vulnerabilities:
- **3 Hardcoded Credentials**: Anthropic API key, AWS secret key, GitHub token
- **Prompt Injection**: User query in agent goal
- **Remote Code Execution**: subprocess.run with shell=True
- **Infinite Loop**: Unbounded data sync retries
- **Unsafe Environment Access**: Missing configuration defaults

**WOW Factor**: Demonstrates RCE vulnerability enabling complete infrastructure takeover

#### Tab 3: Bring Your Own Agent
Dynamic scanning of user-provided code with real-time detection.

### 3. Enhanced Results Display

#### Scan Metrics
Real-time performance indicators:
- **5 Patterns**: Shows simultaneous pattern scanning
- **Lines Analyzed**: Total code lines scanned
- **Execution Time**: Sub-millisecond scan performance (e.g., "3.2ms")

#### Attack Chain Detection
Findings grouped by vulnerability type to show:
- How multiple vulnerabilities create attack chains
- The severity and impact of combined exploits
- Complete picture of security risk

#### Interactive Cross-Highlighting
- Hover over any finding to highlight the vulnerable code line
- Hover over code to see all findings on that line
- Smooth animations and visual feedback

### 4. Professional Design
- **Enterprise Dark Theme**: #0f172a background with blue-to-purple gradients
- **Responsive Layout**: Works perfectly on desktop, tablet, and mobile
- **Smooth Animations**: Professional slide-in effects for findings
- **Visual Hierarchy**: Clear severity indicators (High/Medium/Low)
- **Risk Scoring**: 0-100 risk score with visual metrics

## Demo Structure

```
demo.html
├── Header
│   ├── Inkog Logo & Title
│   ├── Pattern Count Badge (with tooltip)
│   └── Scan/Reset Controls
├── Tab Navigation
│   ├── Compromised Payment Agent
│   ├── Supply Chain Risk Agent
│   └── Bring Your Own Agent
├── Split Panel View
│   ├── Left: Source Code Display
│   │   └── Syntax-highlighted vulnerable code
│   └── Right: Scan Results
│       ├── Scan Metrics
│       ├── Vulnerability Breakdown
│       └── Grouped Findings (by pattern)
└── Bottom Metrics Bar
    ├── Risk Score (e.g., "92/100")
    ├── Issues Found (e.g., "7")
    ├── Scan Time (e.g., "3.2ms")
    └── Accuracy ("100%")
```

## Technical Implementation

### Pattern Detection
The demo implements real pattern detection for:
1. **Credentials**: Matches API keys, passwords, secrets, tokens
2. **Prompt Injection**: Detects f-string user input interpolation
3. **RCE**: Identifies subprocess commands with shell=True
4. **Infinite Loops**: Finds while True without break conditions
5. **Unsafe Env Access**: Catches os.environ[] without .get()

### Code Examples
Both example agents use realistic production-style code:
- Proper class structures and methods
- Real vulnerability patterns seen in production
- Meaningful variable names and contexts
- Comments highlighting attack vectors

### Responsive Design
- **Desktop (>1200px)**: Side-by-side code and results
- **Tablet (768-1200px)**: Stacked vertical layout
- **Mobile (<768px)**: Full-width single column with optimized spacing

## Usage

### Standalone Demo
```bash
# Open directly in browser
open demo/demo.html

# Or use a local server
python3 -m http.server 8000
# Navigate to http://localhost:8000/demo/demo.html
```

### Embedding
```html
<!-- Full-width embed -->
<iframe
  src="https://inkog-io.github.io/inkog-demo/demo.html"
  width="100%"
  height="1000"
  frameborder="0"
  style="border: 1px solid #334155; border-radius: 12px;">
</iframe>

<!-- Container with max-width -->
<div style="max-width: 1600px; margin: 0 auto;">
  <iframe src="path/to/demo.html" width="100%" height="1000"></iframe>
</div>
```

### Sales & Marketing
Perfect for:
- **Product demos**: 2-3 minute live demonstrations
- **Website landing pages**: Interactive showcase of capabilities
- **Conference presentations**: Live vulnerability detection
- **Documentation**: Visual explanation of detection features
- **Social media**: Shareable demo link

## User Experience Flow

1. **First Impression** (0-5 seconds)
   - User sees professional dark interface
   - Pattern badge draws attention: "It's checking 5 patterns?"
   - Clean code example with clear structure

2. **Interaction** (5-30 seconds)
   - User clicks "Scan Code" button
   - Scan metrics appear: "5 patterns, 35 lines, 3.2ms"
   - Findings appear with smooth animations
   - User hovers findings to see code highlighting

3. **WOW Moment** (30-60 seconds)
   - User realizes: "It found the hardcoded keys AND the RCE AND the infinite loop"
   - Sees attack chain: "The credentials can be exfiltrated via the injection"
   - Understands: "This would be a disaster in production"

4. **Exploration** (1-3 minutes)
   - User switches to Supply Chain Risk Agent tab
   - Sees different attack patterns (RCE, AWS compromise)
   - Tries "Bring Your Own Agent" tab with custom code
   - Convinced: "I need to scan our agents"

## Key Differentiators

### vs. Generic Security Demos
- **Real code**: Actual production-style vulnerable agents, not toy examples
- **Multi-pattern**: Shows simultaneous detection of 5 different patterns
- **Attack chains**: Demonstrates how vulnerabilities combine
- **Performance**: Sub-millisecond scanning, not slow analysis

### vs. Static Screenshots
- **Interactive**: Users can scan different agents, paste their own code
- **Dynamic**: Real-time highlighting and cross-referencing
- **Engaging**: Animations and hover effects create memorable experience
- **Convincing**: Users see it working, not just reading about it

## Demo Impact Metrics

**Target User Response:**
- "WOW - it caught the attack chain I completely missed"
- "It's checking 5 patterns simultaneously? That's comprehensive!"
- "This would catch our production vulnerabilities"
- "I need this in our CI/CD pipeline NOW"

**Conversion Goals:**
- Time on demo: 3+ minutes (was 1-2 min with old version)
- Tab switching: 80%+ users explore multiple tabs
- Custom code trial: 40%+ users try "Bring Your Own Agent"
- CTA clicks: 60%+ proceed to integration docs

## Technical Excellence

### No External Dependencies
- Self-contained HTML file
- No CDN requirements
- No backend services
- Works offline

### Performance
- Instant page load
- Smooth 60fps animations
- Sub-millisecond pattern matching
- Responsive interactions

### Accessibility
- Semantic HTML structure
- Proper contrast ratios
- Keyboard navigation support
- Screen reader compatible

### Browser Compatibility
- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (iOS, Android)

## Customization

### Adding New Patterns
Update the pattern badge tooltip and detection logic:
```javascript
// In pattern tooltip HTML
<div class="pattern-item">
    <span class="pattern-item-icon">✓</span>
    <span>Your New Pattern</span>
    <span class="pattern-item-cwe">CWE-XXX</span>
</div>

// In analyzeCustomCode function
if (/your-pattern-regex/.test(line)) {
    findings.push({
        pattern: 'Your New Pattern',
        severity: 'high',
        line: idx + 1,
        message: 'Pattern detected in code',
        cwe: 'CWE-XXX',
        cvss: '8.5',
        group: 'your-group'
    });
}
```

### Changing Color Scheme
Modify CSS variables for consistent theming:
```css
/* Background colors */
--bg-primary: #0f172a;
--bg-secondary: #1e293b;

/* Accent colors */
--accent-blue: #60a5fa;
--accent-purple: #a78bfa;

/* Severity colors */
--severity-high: #ef4444;
--severity-medium: #f59e0b;
--severity-low: #10b981;
```

### Adding New Examples
Create new code examples following the pattern:
```javascript
const yourExampleCode = `# Your vulnerable agent code here
import os
API_KEY = "sk-your-key-here"  # Hardcoded credential
prompt = f"Process: {user_input}"  # Prompt injection
...`;

const yourExampleFindings = [
    {
        pattern: 'Pattern Name',
        severity: 'high',
        line: 2,
        message: 'Detailed explanation',
        cwe: 'CWE-XXX',
        cvss: '9.0',
        group: 'category'
    },
    // ... more findings
];
```

## Maintenance

### Updating for New Inkog Releases
When new patterns are added to Inkog:
1. Update pattern badge count
2. Add new pattern to tooltip
3. Implement detection logic in analyzeCustomCode
4. Add example vulnerable code demonstrating the pattern
5. Test cross-highlighting and grouping

### Testing Checklist
- [ ] All 3 tabs load correctly
- [ ] Pattern badge tooltip displays on hover
- [ ] Scan button triggers analysis
- [ ] Findings appear with animations
- [ ] Cross-highlighting works (hover finding → code, hover code → finding)
- [ ] Risk score calculates correctly
- [ ] Scan metrics display properly
- [ ] Reset button clears state
- [ ] Responsive layout works on mobile
- [ ] Custom code tab accepts user input
- [ ] All vulnerability types detected in custom code

## Future Enhancements

### Potential Additions
1. **Export Results**: Download findings as PDF/JSON
2. **Share Demo**: Generate shareable URL with specific code
3. **Comparison Mode**: Show before/after fixing vulnerabilities
4. **Integration Preview**: Show how Inkog integrates into CI/CD
5. **Live Stats**: Real-world statistics from Inkog scans
6. **Video Walkthrough**: Embedded explanation video

### Advanced Features
1. **Multi-file Support**: Upload and scan multiple agent files
2. **Framework Detection**: Auto-detect LangChain, CrewAI, Autogen
3. **Fix Suggestions**: Show how to remediate each finding
4. **Severity Filtering**: Toggle visibility of High/Medium/Low
5. **Historical Comparison**: Track security posture over time

## Support & Feedback

- **Repository**: https://github.com/inkog-io/inkog-demo
- **Main Project**: https://github.com/inkog-io/inkog
- **Issues**: https://github.com/inkog-io/inkog-demo/issues
- **Email**: support@inkog.io

## License

MIT License - See LICENSE file for details

---

**Demo Status**: Production Ready ✅

The demo showcases Inkog's technical excellence in multi-pattern vulnerability detection for AI agents. It creates compelling "wow moments" that demonstrate why Inkog is essential for securing AI agent deployments.

Last Updated: November 2025
