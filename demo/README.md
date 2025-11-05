# Inkog Interactive Demo

A live, interactive demonstration of Inkog's AI agent security scanning capabilities.

## 🎯 What's Included

### 1. **demo.html** - Interactive Terminal Demo
An embedded, client-side demonstration that:
- Uses **xterm.js** for realistic terminal emulation
- Plays a **pre-recorded security scan** in real-time
- Shows vulnerabilities appearing in the findings panel as they're detected
- Includes **Play**, **Reset**, and **Speed Control** buttons
- Displays **risk score**, **scan duration**, and **findings count** metrics
- Completely **self-contained** - no backend required
- Can be **embedded as an iframe** on any website

**Features:**
- ✅ Auto-plays scan sequence on page load
- ✅ Terminal output simulates real `inkog scan` command
- ✅ Synchronized findings panel shows vulnerabilities as detected
- ✅ Visual severity indicators (🔴 High, 🟠 Medium, 🟡 Low)
- ✅ Responsive design for mobile/tablet/desktop
- ✅ Adjustable playback speed (Slow, Normal, Fast)
- ✅ Professional styling with gradient backgrounds

### 2. **vulnerable-agent.py** - Sample Vulnerable Agent
A realistic Python agent demonstrating the types of security issues Inkog detects:

```python
# ❌ VULNERABILITY #1: Hardcoded API Key (Line 9)
OPENAI_API_KEY = "sk-proj-1234567890abcdefghij1234567890ab"

# ❌ VULNERABILITY #2: Prompt Injection (Line 27)
prompt = f"Search results for: {self.user_query}"  # Direct interpolation

# ❌ VULNERABILITY #3: Infinite Loop (Line 35)
while True:  # Missing break condition
    attempt += 1
    # ... never breaks

# ❌ VULNERABILITY #4: Unsafe Environment Access (Line 51)
db_url = os.environ["DATABASE_URL"]  # No default value

# ❌ VULNERABILITY #5: JWT Secret Hardcoded (Line 64)
JWT_SECRET = "your-secret-key-12345-super-secret-key-exposed"

# ❌ VULNERABILITY #6: Another Prompt Injection (Line 67)
instruction = f"Analyze this user message: {user_message}"
```

Each vulnerability is marked with `❌` comments and includes explanation of why it's dangerous.

## 🚀 Usage

### Option 1: View in Browser (Standalone)
```bash
# Simply open the HTML file in a web browser
open demo/demo.html
# or
firefox demo/demo.html
```

### Option 2: Embed on Website
```html
<!-- Embed as iframe (with sizing) -->
<iframe
  src="https://raw.githubusercontent.com/inkog-io/inkog/main/demo/demo.html"
  width="1200"
  height="800"
  frameborder="0">
</iframe>

<!-- Or with custom sizing -->
<div style="max-width: 1200px; margin: 20px auto;">
  <iframe
    src="path/to/demo.html"
    width="100%"
    height="900"
    frameborder="0"
    allow="fullscreen">
  </iframe>
</div>
```

### Option 3: Integrate into Documentation
```markdown
[View Interactive Demo](https://github.com/inkog-io/inkog/blob/main/demo/demo.html)
```

## 📊 What the Demo Shows

The demo plays through a complete scan sequence:

1. **Command Execution** (Line 1)
   ```
   $ inkog scan vulnerable-agent.py
   🔍 Scanning vulnerable-agent.py for security issues...
   ```

2. **Scan Progress** (Lines 3-7)
   ```
   ========================================
           INKOG SECURITY SCAN REPORT
   ========================================

   Risk Score:       73/100
   Duration:         12.4ms
   Files Scanned:    1
   Lines of Code:    67
   ```

3. **Findings Summary** (Lines 13-16)
   ```
   FINDINGS SUMMARY:
     Total:      3
     🔴 High:    2
     🟠 Medium:  1
     🟡 Low:     0
   ```

4. **Detailed Findings** (Lines 20-35)
   - Finding 1: Hardcoded Credentials (Line 9)
   - Finding 2: Prompt Injection (Line 27)
   - Finding 3: Infinite Loop (Line 35)

## 🎨 Demo Features

### Terminal Emulation
- **Real xterm.js library** for authentic terminal look/feel
- **Cursor blinking** and proper terminal colors
- **Monospace font** matching actual terminal
- **Dark theme** with proper syntax coloring

### Findings Panel
- **Real-time updates** as scan progresses
- **Color-coded severity** badges
- **Code snippet display** showing vulnerable lines
- **CWE identifiers** for each finding
- **Smooth animations** when findings appear

### Metrics Display
- **Risk Score** with color gradient (🟢 Green for safe → 🔴 Red for critical)
- **Files Scanned** counter
- **Findings Count** (automatically incremented)
- **Scan Duration** in milliseconds

### Playback Controls
- **Play Button** - Start or restart the demo
- **Reset Button** - Clear terminal and findings
- **Speed Control** - Choose playback speed:
  - Slow: 1.0x delay (detailed viewing)
  - Normal: 0.6x delay (recommended)
  - Fast: 0.2x delay (quick overview)

## 🔧 Customization

### Modify the Scan Output
Edit the `scanOutput` array in `demo.html` to show different output:

```javascript
const scanOutput = [
    { delay: 0, text: '$ inkog scan your-agent.py\r\n' },
    { delay: 100, text: '🔍 Scanning...\r\n' },
    // Add more lines...
];
```

### Change the Findings
Edit the `findings` array to show different vulnerabilities:

```javascript
const findings = [
    {
        id: 1,
        name: 'Your Finding Name',
        severity: 'high',  // 'high', 'medium', 'low'
        line: 123,
        message: 'Description of the finding',
        cwe: 'CWE-XXX'
    },
    // Add more findings...
];
```

### Customize Colors
Modify the CSS gradient and theme colors:

```css
/* Header gradient */
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);

/* Risk score colors */
.risk-score {
    background: linear-gradient(135deg, #ffc107 0%, #ff6b6b 100%);
}
```

## 📱 Responsive Design

The demo is fully responsive:
- **Desktop**: Full 2-column layout (terminal + findings side-by-side)
- **Tablet**: Stacked layout with adjusted sizing
- **Mobile**: Single column, optimized for small screens

All controls and displays adapt to screen size automatically.

## 🌐 Browser Compatibility

- ✅ Chrome/Chromium (88+)
- ✅ Firefox (87+)
- ✅ Safari (14+)
- ✅ Edge (88+)
- ✅ Mobile browsers (iOS Safari, Chrome Mobile)

Requires JavaScript enabled and modern CSS support.

## 📚 Integration Examples

### Website Footer
```html
<footer>
  <p><a href="/demo">Try our interactive demo →</a></p>
</footer>
```

### Product Page
```html
<section id="demo">
  <h2>See Inkog in Action</h2>
  <iframe src="/demo/demo.html" width="100%" height="900"></iframe>
</section>
```

### GitHub README
```markdown
## 🚀 Live Demo

[Click here to see Inkog scanning a vulnerable agent in real-time!](demo/demo.html)

The demo shows:
- Real terminal output from the Inkog scanner
- 3 security vulnerabilities detected in seconds
- Risk scoring and severity classification
- Complete scan metrics
```

### Marketing Material
Print the demo URL in:
- Product documentation
- Sales presentations
- Blog posts
- GitHub profile
- LinkedIn posts

## 🎓 Educational Value

Perfect for:
- **Teaching security concepts** - Show real AI agent vulnerabilities
- **Sales demos** - Quick 2-minute overview of capabilities
- **Documentation** - Interactive example of how Inkog works
- **Onboarding** - Help new users understand the scanner
- **Marketing** - Impressive, professional demonstration

## 🔒 Security Notes

- **No data collection** - Demo runs 100% client-side
- **No network requests** - All processing in browser
- **No cookies** - Stateless demonstration
- **No backend needed** - Can be hosted on any static server

## 📖 For More Information

- **Main Repository**: https://github.com/inkog-io/inkog
- **Inkog Scanner**: `action/cmd/scanner/main.go`
- **Test Agents**: `test-agents/` directory
- **Documentation**: `Documentation/` directory

---

**Status**: Production Ready ✅

The demo is fully functional and ready for embedding on marketing websites, documentation sites, and promotional materials.

Questions? Create an issue or reach out at hello@inkog.io
