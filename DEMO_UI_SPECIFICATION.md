# Inkog Demo - Business Context UI Specification

## Visual Design Reference

This document provides exact specifications for implementing the Business Risk Assessment component in the Inkog demo.

---

## Layout Integration

### Current Demo Structure
```
┌─────────────────────────────────────────────────────────┐
│  HEADER (Logo, Title, Scan/Reset Buttons)               │
├─────────────────────────────────────────────────────────┤
│  TABS (Langchain | CrewAI | Custom)                     │
├───────────────────────┬─────────────────────────────────┤
│                       │                                 │
│  SOURCE CODE          │  VULNERABILITY FINDINGS         │
│  (Left Panel)         │  (Right Panel - CURRENT)        │
│                       │                                 │
│  [Code with line #s]  │  [8 findings listed]            │
│                       │                                 │
│                       │                                 │
├───────────────────────┴─────────────────────────────────┤
│  METRICS (Risk Score | Issues | Time | Accuracy)        │
└─────────────────────────────────────────────────────────┘
```

### Enhanced Demo Structure (WITH Business Context)
```
┌─────────────────────────────────────────────────────────┐
│  HEADER (Logo, Title, Scan/Reset Buttons)               │
├─────────────────────────────────────────────────────────┤
│  TABS (Langchain | CrewAI | Custom)                     │
├───────────────────────┬─────────────────────────────────┤
│                       │                                 │
│  SOURCE CODE          │  ⚠️  BUSINESS RISK ASSESSMENT   │ ← NEW
│  (Left Panel)         │  ┌───────────────────────────┐  │
│                       │  │ 💰 $2.9M/year potential   │  │
│  [Code with line #s]  │  │ ⚖️  3 compliance violations│  │
│                       │  │ 📊 14 days to incident    │  │
│                       │  │ 🔴 CRITICAL risk level    │  │
│                       │  │                           │  │
│                       │  │ [View Breakdown ▼]        │  │
│                       │  └───────────────────────────┘  │
│                       │                                 │
│                       │  VULNERABILITY FINDINGS         │ ← EXISTING
│                       │  [8 findings listed below]      │
│                       │                                 │
├───────────────────────┴─────────────────────────────────┤
│  METRICS (Risk Score | Issues | Time | Accuracy)        │
└─────────────────────────────────────────────────────────┘
```

**Placement:** Business summary appears ABOVE vulnerability findings in right panel

---

## Component States

### State 1: Collapsed (Initial View)

**Visual Mockup:**
```
┌─────────────────────────────────────────────────────────┐
│  ⚠️  BUSINESS RISK ASSESSMENT                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  💰  Potential Annual Cost: $2.9M                       │
│                                                         │
│  ⚖️   Compliance Violations: 3 major regulations        │
│                                                         │
│  📊  Predicted Incident: 14 days without fix            │
│                                                         │
│  🔴  Overall Risk Level: CRITICAL                       │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │         View Detailed Breakdown ▼               │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Dimensions:**
- Width: 100% of right panel
- Height: ~280px
- Padding: 24px
- Border radius: 8px
- Margin bottom: 20px

**Colors:**
- Background: `linear-gradient(135deg, #7c2d12 0%, #991b1b 100%)` (dark red gradient)
- Border: `2px solid #dc2626` (red-600)
- Text: `#fef2f2` (red-50, off-white)
- Icon color: `#fef2f2`

**Typography:**
- Header: 14px, uppercase, 700 weight, 1.5px letter-spacing
- Metrics: 16px, 600 weight
- Values: 18px, 700 weight
- Button: 14px, 600 weight

**Animation on appearance:**
```css
@keyframes slideInDown {
    from {
        opacity: 0;
        transform: translateY(-20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.business-summary {
    animation: slideInDown 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) 0.3s both;
}
```

**Pulsing glow effect:**
```css
@keyframes pulseGlow {
    0%, 100% {
        box-shadow: 0 8px 24px rgba(220, 38, 38, 0.3);
    }
    50% {
        box-shadow: 0 8px 32px rgba(220, 38, 38, 0.5);
    }
}

.business-summary {
    animation: pulseGlow 2s ease-in-out infinite;
}
```

### State 2: Expanded (After Click)

**Visual Mockup (Scrollable):**
```
┌─────────────────────────────────────────────────────────┐
│  ⚠️  BUSINESS RISK ASSESSMENT          [Collapse ▲]     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  💰  FINANCIAL IMPACT ANALYSIS                          │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  ├─ Infinite Loop (Line 21): $2.1M/year                │
│  │   • GPT-4 API: $0.09/call × 100/day × 365 = $3,285  │
│  │   • AWS Lambda overrun: $3,285 × 12x = $39,420      │
│  │   • Total annual waste: $2,117,500                  │
│  │                                                      │
│  ├─ Hardcoded Credentials (4 findings): $750K/year     │
│  │   • Credential rotation: $15,000                    │
│  │   • Incident response (35% prob): $82,250           │
│  │   • Data breach (25% prob): $500,000                │
│  │                                                      │
│  ├─ Prompt Injection (3 findings): $80K/year           │
│  │   • LLM abuse cost: $45,000                         │
│  │   • Detection/monitoring: $35,000                   │
│  │                                                      │
│  └─ Unsafe Environment Access: $20.5K/year             │
│      • Downtime (2.5h × $5K/h): $12,500                │
│      • Emergency remediation: $8,000                   │
│                                                         │
│  Total Annual Cost: $2,945,000                         │
│                                                         │
│  ⚖️  REGULATORY COMPLIANCE VIOLATIONS                   │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  ├─ EU AI Act Article 15 (High-Risk AI Systems)        │
│  │   • Violation: Hardcoded credentials in AI system   │
│  │   • Penalty: €20M or 4% global revenue              │
│  │   • Enforcement: August 2, 2026 (270 days)          │
│  │   • Geography: EU/EEA                               │
│  │                                                      │
│  ├─ GDPR Article 32 (Security of Processing)           │
│  │   • Violation: Inadequate security measures         │
│  │   • Penalty: €50M or 4% global revenue              │
│  │   • Risk: Data exposure via prompt injection        │
│  │   • Geography: EU/EEA + international               │
│  │                                                      │
│  └─ SOC 2 Type II - CC6.1 (Logical Access)             │
│      • Violation: Inadequate credential management     │
│      • Impact: Audit failure, contract breach          │
│      • Geography: Global (US-focused)                  │
│                                                         │
│  📊  INCIDENT PREDICTION & PRECEDENT                    │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Stripe - Infinite Loop (May 2023)               │   │
│  │ ─────────────────────────────────────────────── │   │
│  │ Pattern: Missing break in retry logic           │   │
│  │ Cost: $197,400 (4.2 hour outage)                │   │
│  │ Match: 95% similar to Line 21                   │   │
│  │ [Read More →]                                   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Twitch - Credential Exposure (Oct 2021)         │   │
│  │ ─────────────────────────────────────────────── │   │
│  │ Data: 125GB source + 125M user records          │   │
│  │ Cost: $12.5M+ (breach + fines)                  │   │
│  │ Match: 100% similar to Lines 7, 8, 34           │   │
│  │ [Read More →]                                   │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  🔴  RISK TIMELINE PROJECTION                           │
│  ─────────────────────────────────────────────────────  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │                                                 │   │
│  │  Day 1-7   │ ░░░░░░░░░░░░░░░ 15% probability   │   │
│  │  Low traffic, edge cases only                  │   │
│  │                                                 │   │
│  │  Day 7-14  │ ████████████████████ 60% prob     │   │
│  │  Peak hours trigger infinite loop              │   │
│  │                                                 │   │
│  │  Day 14+   │ ██████████████████████████ 87%    │   │
│  │  Production incident LIKELY ⚠️                  │   │
│  │                                                 │   │
│  │  Day 30+   │ ████████████████████████████ 99%  │   │
│  │  Guaranteed failure at scale 🔴                │   │
│  │                                                 │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Critical Path: Infinite Loop (Line 21)                │
│  Predicted Incident: 14 days without fix               │
│  Risk Level: CRITICAL - Immediate action required      │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Collapse Details ▲                 │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Dimensions:**
- Width: 100% of right panel
- Height: Auto (scrollable, max-height: 1200px)
- Padding: 24px
- Internal spacing: 16px between sections

**Section Headers:**
- Font: 16px, 700 weight, uppercase, 1px letter-spacing
- Color: `#fef2f2`
- Border bottom: 1px solid rgba(255, 255, 255, 0.2)
- Margin bottom: 16px

**Cost Breakdown Items:**
- Indent: 12px (tree structure: ├─ └─)
- Font: 14px, 400 weight for description, 600 weight for values
- Line height: 1.6
- Hover effect: Background rgba(255, 255, 255, 0.05), translateX(4px)

**Incident Cards:**
- Background: rgba(0, 0, 0, 0.2)
- Border left: 3px solid #f59e0b (amber-500)
- Padding: 16px
- Margin: 8px 0
- Border radius: 6px
- Hover: Background rgba(0, 0, 0, 0.3), border-left-color #fbbf24

**Timeline Bars:**
- Background: rgba(255, 255, 255, 0.1) (empty state)
- Fill color: Gradient based on probability
  - 0-30%: `#10b981` (green)
  - 30-60%: `#f59e0b` (amber)
  - 60-85%: `#ef4444` (red)
  - 85-100%: `#991b1b` (dark red)
- Height: 24px
- Border radius: 4px
- Animation: Width animates from 0 to final value over 1s

**Expand/Collapse Transition:**
```css
.business-details {
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.6s cubic-bezier(0.4, 0, 0.2, 1),
                opacity 0.4s ease;
    opacity: 0;
}

.business-details.expanded {
    max-height: 2000px; /* Large enough for all content */
    opacity: 1;
}
```

---

## HTML Structure

```html
<div class="business-summary" id="businessSummary">
    <!-- Header -->
    <div class="business-header">
        <div class="business-header-left">
            <span class="business-icon">⚠️</span>
            <span class="business-title">BUSINESS RISK ASSESSMENT</span>
        </div>
        <button class="business-toggle" id="toggleButton" onclick="toggleBusinessSummary()">
            <span id="toggleText">View Breakdown</span>
            <span id="toggleIcon">▼</span>
        </button>
    </div>

    <!-- Collapsed Summary Metrics -->
    <div class="business-metrics-summary">
        <div class="business-metric">
            <span class="metric-icon">💰</span>
            <span class="metric-label">Potential Annual Cost:</span>
            <span class="metric-value" id="totalCost">$2.9M</span>
        </div>

        <div class="business-metric">
            <span class="metric-icon">⚖️</span>
            <span class="metric-label">Compliance Violations:</span>
            <span class="metric-value" id="complianceCount">3 major regulations</span>
        </div>

        <div class="business-metric">
            <span class="metric-icon">📊</span>
            <span class="metric-label">Predicted Incident:</span>
            <span class="metric-value" id="incidentDays">14 days without fix</span>
        </div>

        <div class="business-metric">
            <span class="metric-icon">🔴</span>
            <span class="metric-label">Overall Risk Level:</span>
            <span class="metric-value" id="riskLevel">CRITICAL</span>
        </div>
    </div>

    <!-- Expanded Details (Initially Hidden) -->
    <div class="business-details" id="businessDetails">
        <!-- Financial Impact Section -->
        <div class="business-section">
            <div class="section-header">
                <span class="section-icon">💰</span>
                <span class="section-title">FINANCIAL IMPACT ANALYSIS</span>
            </div>
            <div class="section-content" id="financialContent">
                <!-- Dynamically populated cost breakdown -->
            </div>
        </div>

        <!-- Compliance Section -->
        <div class="business-section">
            <div class="section-header">
                <span class="section-icon">⚖️</span>
                <span class="section-title">REGULATORY COMPLIANCE VIOLATIONS</span>
            </div>
            <div class="section-content" id="complianceContent">
                <!-- Dynamically populated compliance violations -->
            </div>
        </div>

        <!-- Incidents Section -->
        <div class="business-section">
            <div class="section-header">
                <span class="section-icon">📊</span>
                <span class="section-title">INCIDENT PREDICTION & PRECEDENT</span>
            </div>
            <div class="section-content" id="incidentsContent">
                <!-- Dynamically populated incident cards -->
            </div>
        </div>

        <!-- Risk Timeline Section -->
        <div class="business-section">
            <div class="section-header">
                <span class="section-icon">🔴</span>
                <span class="section-title">RISK TIMELINE PROJECTION</span>
            </div>
            <div class="section-content" id="timelineContent">
                <!-- Dynamically populated timeline visualization -->
            </div>
        </div>
    </div>
</div>
```

---

## CSS Stylesheet

```css
/* Business Summary Container */
.business-summary {
    background: linear-gradient(135deg, #7c2d12 0%, #991b1b 100%);
    border: 2px solid #dc2626;
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 20px;
    box-shadow: 0 8px 24px rgba(220, 38, 38, 0.3);
    animation: slideInDown 0.5s cubic-bezier(0.34, 1.56, 0.64, 1) 0.3s both,
               pulseGlow 2s ease-in-out infinite;
}

@keyframes slideInDown {
    from {
        opacity: 0;
        transform: translateY(-20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes pulseGlow {
    0%, 100% {
        box-shadow: 0 8px 24px rgba(220, 38, 38, 0.3);
    }
    50% {
        box-shadow: 0 8px 32px rgba(220, 38, 38, 0.5);
    }
}

/* Header */
.business-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.business-header-left {
    display: flex;
    align-items: center;
    gap: 12px;
}

.business-icon {
    font-size: 24px;
}

.business-title {
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: #fef2f2;
}

.business-toggle {
    background: rgba(255, 255, 255, 0.1);
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: #fef2f2;
    padding: 10px 20px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 8px;
}

.business-toggle:hover {
    background: rgba(255, 255, 255, 0.2);
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

/* Summary Metrics */
.business-metrics-summary {
    display: flex;
    flex-direction: column;
    gap: 16px;
}

.business-metric {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    font-size: 16px;
    font-weight: 600;
    color: #fef2f2;
}

.business-metric:last-child {
    border-bottom: none;
}

.metric-icon {
    font-size: 24px;
    min-width: 32px;
}

.metric-label {
    flex: 1;
}

.metric-value {
    font-weight: 700;
    font-size: 18px;
    color: #fff;
}

/* Expanded Details */
.business-details {
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.6s cubic-bezier(0.4, 0, 0.2, 1),
                opacity 0.4s ease;
    opacity: 0;
}

.business-details.expanded {
    max-height: 2000px;
    opacity: 1;
    margin-top: 24px;
}

/* Section Styling */
.business-section {
    margin-bottom: 24px;
}

.business-section:last-child {
    margin-bottom: 0;
}

.section-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.2);
}

.section-icon {
    font-size: 20px;
}

.section-title {
    font-size: 16px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #fef2f2;
}

.section-content {
    color: #fecaca; /* red-200 */
    font-size: 14px;
    line-height: 1.6;
}

/* Cost Breakdown Items */
.cost-item {
    margin-left: 12px;
    margin-bottom: 16px;
    padding: 8px 12px;
    border-radius: 4px;
    transition: all 0.3s ease;
}

.cost-item:hover {
    background: rgba(255, 255, 255, 0.05);
    transform: translateX(4px);
}

.cost-item-header {
    font-weight: 600;
    font-size: 15px;
    color: #fef2f2;
    margin-bottom: 8px;
}

.cost-item-detail {
    margin-left: 16px;
    margin-bottom: 4px;
    color: #fecaca;
    font-size: 13px;
}

.cost-item-total {
    margin-left: 16px;
    font-weight: 600;
    color: #fff;
    margin-top: 8px;
}

/* Compliance Violation Items */
.compliance-item {
    margin-bottom: 20px;
    padding: 12px;
    background: rgba(0, 0, 0, 0.15);
    border-left: 3px solid #fbbf24; /* amber-400 */
    border-radius: 4px;
}

.compliance-item-name {
    font-weight: 700;
    font-size: 15px;
    color: #fef2f2;
    margin-bottom: 8px;
}

.compliance-item-detail {
    margin-bottom: 6px;
    color: #fecaca;
    font-size: 13px;
}

.compliance-item-detail strong {
    color: #fef2f2;
    font-weight: 600;
}

/* Incident Cards */
.incident-card {
    background: rgba(0, 0, 0, 0.2);
    border-left: 3px solid #f59e0b; /* amber-500 */
    padding: 16px;
    margin: 8px 0;
    border-radius: 6px;
    transition: all 0.3s ease;
    cursor: pointer;
}

.incident-card:hover {
    background: rgba(0, 0, 0, 0.3);
    border-left-color: #fbbf24;
    transform: translateX(4px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.incident-card-header {
    font-weight: 700;
    font-size: 15px;
    color: #fef2f2;
    margin-bottom: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.incident-card-date {
    font-size: 12px;
    color: #fecaca;
    font-weight: 400;
}

.incident-card-detail {
    margin-bottom: 6px;
    color: #fecaca;
    font-size: 13px;
}

.incident-card-link {
    color: #fbbf24;
    text-decoration: none;
    font-size: 13px;
    font-weight: 600;
    margin-top: 8px;
    display: inline-block;
}

.incident-card-link:hover {
    color: #fde047; /* amber-300 */
    text-decoration: underline;
}

/* Risk Timeline */
.timeline-container {
    background: rgba(0, 0, 0, 0.15);
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 16px;
}

.timeline-item {
    margin-bottom: 16px;
    padding-bottom: 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.timeline-item:last-child {
    border-bottom: none;
    margin-bottom: 0;
    padding-bottom: 0;
}

.timeline-item-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.timeline-item-period {
    font-weight: 600;
    color: #fef2f2;
    font-size: 14px;
}

.timeline-item-probability {
    font-size: 13px;
    color: #fecaca;
    font-weight: 600;
}

.timeline-item-bar {
    width: 100%;
    height: 24px;
    background: rgba(255, 255, 255, 0.1);
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 6px;
}

.timeline-item-bar-fill {
    height: 100%;
    border-radius: 4px;
    transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
    animation: expandWidth 1s ease-out;
}

@keyframes expandWidth {
    from {
        width: 0;
    }
}

.timeline-item-bar-fill.low {
    background: linear-gradient(90deg, #10b981 0%, #34d399 100%);
}

.timeline-item-bar-fill.medium {
    background: linear-gradient(90deg, #f59e0b 0%, #fbbf24 100%);
}

.timeline-item-bar-fill.high {
    background: linear-gradient(90deg, #ef4444 0%, #f87171 100%);
}

.timeline-item-bar-fill.critical {
    background: linear-gradient(90deg, #991b1b 0%, #dc2626 100%);
}

.timeline-item-description {
    color: #fecaca;
    font-size: 13px;
}

.timeline-summary {
    margin-top: 16px;
    padding-top: 16px;
    border-top: 1px solid rgba(255, 255, 255, 0.2);
    font-size: 14px;
    color: #fef2f2;
}

.timeline-summary-item {
    margin-bottom: 6px;
}

.timeline-summary-item strong {
    font-weight: 700;
    color: #fff;
}

/* Responsive Design */
@media (max-width: 1199px) {
    .business-summary {
        order: -1; /* Move to top on smaller screens */
    }
}

@media (max-width: 767px) {
    .business-summary {
        padding: 16px;
        font-size: 14px;
    }

    .business-title {
        font-size: 12px;
    }

    .business-metric {
        flex-direction: column;
        align-items: flex-start;
        gap: 6px;
    }

    .metric-value {
        font-size: 16px;
    }

    .business-toggle {
        width: 100%;
        justify-content: center;
    }

    .section-title {
        font-size: 14px;
    }

    .cost-item-header,
    .compliance-item-name,
    .incident-card-header {
        font-size: 14px;
    }
}
```

---

## JavaScript Implementation

```javascript
// Toggle business summary expansion
function toggleBusinessSummary() {
    const details = document.getElementById('businessDetails');
    const toggleText = document.getElementById('toggleText');
    const toggleIcon = document.getElementById('toggleIcon');

    if (details.classList.contains('expanded')) {
        // Collapse
        details.classList.remove('expanded');
        toggleText.textContent = 'View Breakdown';
        toggleIcon.textContent = '▼';

        // Track analytics
        if (typeof analytics !== 'undefined') {
            analytics.track('Business Summary Collapsed');
        }
    } else {
        // Expand
        details.classList.add('expanded');
        toggleText.textContent = 'Collapse';
        toggleIcon.textContent = '▲';

        // Scroll summary into view if needed
        setTimeout(() => {
            details.scrollIntoView({
                behavior: 'smooth',
                block: 'nearest'
            });
        }, 100);

        // Track analytics
        if (typeof analytics !== 'undefined') {
            analytics.track('Business Summary Expanded', {
                time_on_page: Math.floor((Date.now() - pageLoadTime) / 1000)
            });
        }
    }
}

// Render business summary after scan completes
function renderBusinessSummary(findings) {
    // Calculate metrics
    const financial = calculateFinancialImpact(findings);
    const compliance = getComplianceViolations(findings);
    const incidents = getIncidentPrecedents(findings);
    const timeline = calculateIncidentPrediction(findings);

    // Update collapsed summary metrics
    document.getElementById('totalCost').textContent =
        `$${(financial.total / 1000000).toFixed(1)}M`;

    document.getElementById('complianceCount').textContent =
        `${compliance.length} major regulations`;

    document.getElementById('incidentDays').textContent =
        `${timeline.predictedDays} days without fix`;

    document.getElementById('riskLevel').textContent =
        timeline.riskLevel;

    // Populate financial breakdown
    const financialContent = document.getElementById('financialContent');
    financialContent.innerHTML = renderFinancialBreakdown(financial);

    // Populate compliance violations
    const complianceContent = document.getElementById('complianceContent');
    complianceContent.innerHTML = renderComplianceViolations(compliance);

    // Populate incidents
    const incidentsContent = document.getElementById('incidentsContent');
    incidentsContent.innerHTML = renderIncidents(incidents);

    // Populate timeline
    const timelineContent = document.getElementById('timelineContent');
    timelineContent.innerHTML = renderTimeline(timeline);

    // Show the summary
    const summary = document.getElementById('businessSummary');
    summary.style.display = 'block';
}

// Helper function: Render financial breakdown
function renderFinancialBreakdown(financial) {
    let html = '';

    financial.breakdowns.forEach(item => {
        html += `
            <div class="cost-item">
                <div class="cost-item-header">
                    ├─ ${item.pattern} (Line ${item.line}): $${(item.cost / 1000).toFixed(0)}K/year
                </div>
                ${item.explanation.map(exp => `
                    <div class="cost-item-detail">• ${exp}</div>
                `).join('')}
            </div>
        `;
    });

    html += `
        <div class="cost-item-total">
            <strong>Total Annual Cost: $${financial.total.toLocaleString()}</strong>
        </div>
    `;

    return html;
}

// Helper function: Render compliance violations
function renderComplianceViolations(violations) {
    return violations.map(reg => `
        <div class="compliance-item">
            <div class="compliance-item-name">
                ├─ ${reg.name} ${reg.article ? reg.article : ''}
            </div>
            <div class="compliance-item-detail">
                • <strong>Violation:</strong> ${reg.violation}
            </div>
            <div class="compliance-item-detail">
                • <strong>Penalty:</strong> ${reg.penalty.tier2 || reg.penalty.tier1}
            </div>
            ${reg.enforcement ? `
                <div class="compliance-item-detail">
                    • <strong>Enforcement:</strong> ${reg.enforcement}
                </div>
            ` : ''}
            <div class="compliance-item-detail">
                • <strong>Geography:</strong> ${reg.geography}
            </div>
        </div>
    `).join('');
}

// Helper function: Render incidents
function renderIncidents(incidents) {
    return incidents.map(incident => `
        <div class="incident-card">
            <div class="incident-card-header">
                <span>${incident.company} - ${incident.pattern}</span>
                <span class="incident-card-date">${incident.date}</span>
            </div>
            <div class="incident-card-detail">
                <strong>Pattern:</strong> ${incident.impact.rootCause}
            </div>
            <div class="incident-card-detail">
                <strong>Cost:</strong> ${incident.impact.cost}
                ${incident.impact.duration ? `(${incident.impact.duration})` : ''}
            </div>
            <div class="incident-card-detail">
                <strong>Match:</strong> ${incident.similarity}% similar to Line ${incident.relatedFinding.line}
            </div>
            ${incident.url ? `
                <a href="${incident.url}" target="_blank" class="incident-card-link">
                    Read More →
                </a>
            ` : ''}
        </div>
    `).join('');
}

// Helper function: Render timeline
function renderTimeline(timeline) {
    let html = '<div class="timeline-container">';

    timeline.escalationTimeline.forEach((phase, index) => {
        const probability = parseInt(phase.probability);
        let severity = 'low';
        if (probability > 80) severity = 'critical';
        else if (probability > 60) severity = 'high';
        else if (probability > 30) severity = 'medium';

        html += `
            <div class="timeline-item">
                <div class="timeline-item-header">
                    <span class="timeline-item-period">Day ${phase.days}</span>
                    <span class="timeline-item-probability">${phase.probability} probability</span>
                </div>
                <div class="timeline-item-bar">
                    <div class="timeline-item-bar-fill ${severity}"
                         style="width: ${probability}%"></div>
                </div>
                <div class="timeline-item-description">
                    ${phase.description}
                </div>
            </div>
        `;
    });

    html += '</div>';

    html += `
        <div class="timeline-summary">
            <div class="timeline-summary-item">
                <strong>Critical Path:</strong> ${timeline.criticalPath.pattern} (Line ${timeline.criticalPath.line})
            </div>
            <div class="timeline-summary-item">
                <strong>Predicted Incident:</strong> ${timeline.predictedDays} days without fix
            </div>
            <div class="timeline-summary-item">
                <strong>Risk Level:</strong> ${timeline.riskLevel} - Immediate action required
            </div>
        </div>
    `;

    return html;
}

// Hook into existing scan function
function scanCode() {
    // ... existing scan logic ...

    // After findings are populated
    renderBusinessSummary(currentFindings);

    // Track scan event
    if (typeof analytics !== 'undefined') {
        analytics.track('Scan Executed', {
            tab: currentTab,
            findings_count: currentFindings.length,
            risk_score: calculateRiskScore(currentFindings),
            has_business_context: true
        });
    }
}
```

---

## Integration Checklist

- [ ] Copy HTML structure into demo.html (after findings panel header)
- [ ] Copy CSS stylesheet into `<style>` section
- [ ] Copy JavaScript functions into `<script>` section
- [ ] Update `scanCode()` function to call `renderBusinessSummary()`
- [ ] Test on all 3 tabs (LangChain, CrewAI, Custom)
- [ ] Verify expand/collapse works smoothly
- [ ] Test on mobile (responsive layout)
- [ ] Verify analytics tracking (if implemented)
- [ ] QA cross-browser (Chrome, Firefox, Safari, Edge)
- [ ] Performance test (Lighthouse score >90)

---

**Document Version:** 1.0
**Last Updated:** November 6, 2025
**Status:** Ready for Implementation
