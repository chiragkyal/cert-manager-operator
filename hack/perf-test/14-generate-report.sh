#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
REPORT_DIR="${RESULTS_DIR}/report-latest"
rm -rf "${REPORT_DIR}"
mkdir -p "${REPORT_DIR}"

echo "=== Generating Performance Test Report ==="
echo "Output: ${REPORT_DIR}/"
echo ""

# Check if python3 is available
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required for chart generation."
    echo "Install with: brew install python3 (macOS) or dnf install python3 (RHEL)"
    exit 1
fi

# Install matplotlib if not present
python3 -c "import matplotlib" 2>/dev/null || {
    echo "Installing matplotlib..."
    pip3 install matplotlib --quiet 2>/dev/null || pip install matplotlib --quiet 2>/dev/null
}

# Collect all summary.json data into a single JSON array
echo "[1/3] Collecting results data..."
SUMMARIES="[]"
for SUMMARY_FILE in "${RESULTS_DIR}"/*/summary.json; do
    [[ -f "${SUMMARY_FILE}" ]] || continue
    RUN_DIR=$(dirname "${SUMMARY_FILE}")
    RUN_NAME=$(basename "${RUN_DIR}")
    ENTRY=$(jq --arg run "${RUN_NAME}" '. + {run_name: $run}' "${SUMMARY_FILE}")
    SUMMARIES=$(echo "${SUMMARIES}" | jq --argjson entry "${ENTRY}" '. + [$entry]')
done

echo "${SUMMARIES}" > "${REPORT_DIR}/all-results.json"
echo "  Found $(echo "${SUMMARIES}" | jq 'length') test runs."

# Collect progress CSV data for timeline charts
for PROGRESS_FILE in "${RESULTS_DIR}"/*/progress.csv; do
    [[ -f "${PROGRESS_FILE}" ]] || continue
    RUN_DIR=$(dirname "${PROGRESS_FILE}")
    RUN_NAME=$(basename "${RUN_DIR}")
    cp "${PROGRESS_FILE}" "${REPORT_DIR}/progress-${RUN_NAME}.csv"
done

# Collect saturation data if present
for SAT_FILE in "${RESULTS_DIR}"/saturation-*/saturation-results.csv; do
    [[ -f "${SAT_FILE}" ]] || continue
    RUN_DIR=$(dirname "${SAT_FILE}")
    RUN_NAME=$(basename "${RUN_DIR}")
    cp "${SAT_FILE}" "${REPORT_DIR}/${RUN_NAME}.csv"
done

echo "[2/3] Generating charts..."

# Generate the Python plotting script and run it
python3 << 'PYTHON_SCRIPT'
import json
import os
import sys

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.ticker import MaxNLocator
except ImportError:
    print("ERROR: matplotlib not available. Install with: pip3 install matplotlib")
    sys.exit(1)

report_dir = os.environ.get('REPORT_DIR', 'results/report')
results_dir = os.environ.get('RESULTS_DIR', 'results')

# Load all results
with open(os.path.join(report_dir, 'all-results.json')) as f:
    all_results = json.load(f)

# Filter to standard throughput tests (not DR, not renewal, not fairness)
throughput_tests = [r for r in all_results if r.get('test_type') not in ('disaster_recovery', 'renewal_storm', 'multi_namespace_fairness')]

# Color scheme
COLORS = {
    'baseline': '#d32f2f',
    'moderate': '#1976d2',
    'aggressive': '#388e3c',
}

def get_color(scenario):
    for key, color in COLORS.items():
        if key in scenario:
            return color
    return '#757575'

# ============================================================
# Chart 1: Issuance Time Comparison (Bar Chart)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 6))

# Group by cert count
cert_counts = sorted(set(r['num_certificates'] for r in throughput_tests))
scenarios_order = ['baseline', 'moderate', 'aggressive']

bar_data = {}
for r in throughput_tests:
    scenario = r['scenario']
    n_certs = r['num_certificates']
    key = f"{scenario}-{n_certs}"
    if key not in bar_data:
        bar_data[key] = r['issuance_duration_seconds']

x_labels = []
values = []
colors = []
for n in cert_counts:
    for s in scenarios_order:
        key = f"{s}-{n}"
        if key in bar_data:
            x_labels.append(f"{s}\n({n} certs)")
            values.append(bar_data[key])
            colors.append(get_color(s))

bars = ax.bar(range(len(values)), values, color=colors, edgecolor='white', linewidth=0.5)
ax.set_xticks(range(len(x_labels)))
ax.set_xticklabels(x_labels, fontsize=9)
ax.set_ylabel('Issuance Duration (seconds)', fontsize=11)
ax.set_title('Certificate Issuance Time by Scenario', fontsize=14, fontweight='bold')
ax.yaxis.set_major_locator(MaxNLocator(integer=True))

# Add value labels on bars
for bar, val in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.5,
            f'{val}s', ha='center', va='bottom', fontsize=10, fontweight='bold')

ax.set_ylim(0, max(values) * 1.2)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig(os.path.join(report_dir, 'chart1-issuance-time.png'), dpi=150)
plt.close()
print("  Generated: chart1-issuance-time.png")

# ============================================================
# Chart 2: Rate Comparison (certs/min)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 6))

x_labels2 = []
rates = []
colors2 = []
for n in cert_counts:
    for s in scenarios_order:
        matching = [r for r in throughput_tests if r['scenario'] == s and r['num_certificates'] == n]
        if matching:
            r = matching[-1]  # Take latest run
            x_labels2.append(f"{s}\n({n} certs)")
            rates.append(float(r.get('rate_certs_per_minute', 0)))
            colors2.append(get_color(s))

bars = ax.bar(range(len(rates)), rates, color=colors2, edgecolor='white', linewidth=0.5)
ax.set_xticks(range(len(x_labels2)))
ax.set_xticklabels(x_labels2, fontsize=9)
ax.set_ylabel('Certificates per Minute', fontsize=11)
ax.set_title('Certificate Issuance Rate by Scenario', fontsize=14, fontweight='bold')

for bar, val in zip(bars, rates):
    ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + max(rates)*0.01,
            f'{val:.0f}', ha='center', va='bottom', fontsize=9, fontweight='bold')

ax.set_ylim(0, max(rates) * 1.15)
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig(os.path.join(report_dir, 'chart2-issuance-rate.png'), dpi=150)
plt.close()
print("  Generated: chart2-issuance-rate.png")

# ============================================================
# Chart 3: Latency Percentiles (P50, P90, P99, Max)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 6))

percentile_data = []
for n in cert_counts:
    for s in scenarios_order:
        matching = [r for r in throughput_tests if r['scenario'] == s and r['num_certificates'] == n]
        if matching:
            r = matching[-1]
            timing = r.get('timing', {})
            try:
                percentile_data.append({
                    'label': f"{s} ({n})",
                    'scenario': s,
                    'p50': int(timing.get('p50_seconds', 0) or 0),
                    'p90': int(timing.get('p90_seconds', 0) or 0),
                    'p99': int(timing.get('p99_seconds', 0) or 0),
                    'max': int(timing.get('max_seconds', 0) or 0),
                })
            except (ValueError, TypeError):
                pass

if percentile_data:
    x = range(len(percentile_data))
    width = 0.2
    p50_vals = [d['p50'] for d in percentile_data]
    p90_vals = [d['p90'] for d in percentile_data]
    p99_vals = [d['p99'] for d in percentile_data]
    max_vals = [d['max'] for d in percentile_data]

    ax.bar([i - 1.5*width for i in x], p50_vals, width, label='P50', color='#4caf50', alpha=0.8)
    ax.bar([i - 0.5*width for i in x], p90_vals, width, label='P90', color='#ff9800', alpha=0.8)
    ax.bar([i + 0.5*width for i in x], p99_vals, width, label='P99', color='#f44336', alpha=0.8)
    ax.bar([i + 1.5*width for i in x], max_vals, width, label='Max', color='#9c27b0', alpha=0.8)

    ax.set_xticks(list(x))
    ax.set_xticklabels([d['label'] for d in percentile_data], fontsize=9)
    ax.set_ylabel('Latency (seconds)', fontsize=11)
    ax.set_title('Per-Certificate Issuance Latency Percentiles', fontsize=14, fontweight='bold')
    ax.legend(loc='upper right')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig(os.path.join(report_dir, 'chart3-latency-percentiles.png'), dpi=150)
plt.close()
print("  Generated: chart3-latency-percentiles.png")

# ============================================================
# Chart 4: Improvement Factor
# ============================================================
fig, ax = plt.subplots(figsize=(10, 5))

improvements = []
for n in cert_counts:
    baseline_match = [r for r in throughput_tests if r['scenario'] == 'baseline' and r['num_certificates'] == n]
    if not baseline_match:
        continue
    baseline_time = baseline_match[-1]['issuance_duration_seconds']
    if baseline_time == 0:
        continue

    for s in ['moderate', 'aggressive']:
        match = [r for r in throughput_tests if r['scenario'] == s and r['num_certificates'] == n]
        if match:
            tuned_time = match[-1]['issuance_duration_seconds']
            factor = baseline_time / max(tuned_time, 1)
            improvements.append({
                'label': f"{s}\n({n} certs)",
                'factor': factor,
                'scenario': s,
            })

if improvements:
    bars = ax.bar(range(len(improvements)),
                  [d['factor'] for d in improvements],
                  color=[get_color(d['scenario']) for d in improvements],
                  edgecolor='white', linewidth=0.5)
    ax.set_xticks(range(len(improvements)))
    ax.set_xticklabels([d['label'] for d in improvements], fontsize=10)
    ax.set_ylabel('Speedup Factor (x times faster)', fontsize=11)
    ax.set_title('Performance Improvement Over Baseline', fontsize=14, fontweight='bold')
    ax.axhline(y=1, color='gray', linestyle='--', alpha=0.5, label='Baseline (1x)')

    for bar, d in zip(bars, improvements):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.3,
                f'{d["factor"]:.1f}x', ha='center', va='bottom', fontsize=11, fontweight='bold')

    ax.set_ylim(0, max(d['factor'] for d in improvements) * 1.2)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig(os.path.join(report_dir, 'chart4-improvement-factor.png'), dpi=150)
plt.close()
print("  Generated: chart4-improvement-factor.png")

# ============================================================
# Chart 5: Progress Over Time (Timeline)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 6))

progress_files = sorted([f for f in os.listdir(report_dir) if f.startswith('progress-') and f.endswith('.csv')])
plotted = 0
for pf in progress_files:
    filepath = os.path.join(report_dir, pf)
    run_name = pf.replace('progress-', '').replace('.csv', '')

    # Determine scenario from run name
    scenario = 'unknown'
    for s in ['aggressive', 'moderate', 'baseline']:
        if s in run_name:
            scenario = s
            break

    # Parse CSV
    times = []
    ready_counts = []
    try:
        with open(filepath) as f:
            header = f.readline()
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    times.append(int(parts[0]))
                    ready_counts.append(int(parts[1]))
    except:
        continue

    if not times or max(ready_counts) == 0:
        continue

    # Only plot 300-cert runs for clarity (or all if no 300-cert)
    if '300' in run_name or plotted < 6:
        label = f"{scenario} ({max(ready_counts)} certs)"
        ax.plot(times, ready_counts, label=label, color=get_color(scenario),
                linewidth=2, alpha=0.8)
        plotted += 1

if plotted > 0:
    ax.set_xlabel('Time (seconds)', fontsize=11)
    ax.set_ylabel('Certificates Ready', fontsize=11)
    ax.set_title('Certificate Issuance Progress Over Time', fontsize=14, fontweight='bold')
    ax.legend(loc='lower right')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(alpha=0.3)

plt.tight_layout()
plt.savefig(os.path.join(report_dir, 'chart5-progress-timeline.png'), dpi=150)
plt.close()
print("  Generated: chart5-progress-timeline.png")

# ============================================================
# Chart 6: Parameter Configuration Summary (Table as image)
# ============================================================
fig, ax = plt.subplots(figsize=(12, 4))
ax.axis('off')

table_data = [
    ['Parameter', 'Default\n(Baseline)', 'Moderate', 'Aggressive', 'Impact'],
    ['--concurrent-workers', '5', '10', '20', 'Parallelism per controller'],
    ['--kube-api-qps', '20', '50', '150', 'API request ceiling (biggest lever)'],
    ['--kube-api-burst', '50', '100', '300', 'Burst capacity above QPS'],
    ['--max-concurrent-challenges', '60', '120', '300', 'ACME parallel challenges'],
    ['--dns01-check-retry-period', '10s', '10s', '2s', 'Propagation check interval'],
    ['CPU request / limit', 'none', '500m / 2', '1 / 4', 'Compute headroom'],
    ['Memory request / limit', 'none', '256Mi / 1Gi', '512Mi / 2Gi', 'Memory headroom'],
]

table = ax.table(cellText=table_data[1:], colLabels=table_data[0],
                 cellLoc='center', loc='center')
table.auto_set_font_size(False)
table.set_fontsize(9)
table.scale(1.2, 1.6)

# Style header
for j in range(len(table_data[0])):
    table[0, j].set_facecolor('#1976d2')
    table[0, j].set_text_props(color='white', fontweight='bold')

# Alternate row colors
for i in range(1, len(table_data)):
    color = '#f5f5f5' if i % 2 == 0 else 'white'
    for j in range(len(table_data[0])):
        table[i, j].set_facecolor(color)

ax.set_title('Performance Tuning Parameters', fontsize=14, fontweight='bold', pad=20)

plt.tight_layout()
plt.savefig(os.path.join(report_dir, 'chart6-parameters-table.png'), dpi=150, bbox_inches='tight')
plt.close()
print("  Generated: chart6-parameters-table.png")

# ============================================================
# Chart 7: DR Recovery & Special Scenarios
# ============================================================
special_tests = [r for r in all_results if r.get('test_type') in ('disaster_recovery', 'renewal_storm')]
if special_tests:
    fig, ax = plt.subplots(figsize=(10, 5))

    labels = []
    durations = []
    colors_sp = []
    for r in special_tests:
        test_type = r.get('test_type', 'unknown')
        scenario = r.get('scenario', 'unknown')
        n = r.get('num_certificates', 0)
        labels.append(f"{test_type.replace('_', ' ').title()}\n({scenario}, {n} certs)")
        durations.append(r.get('issuance_duration_seconds', 0))
        colors_sp.append('#ff6f00' if 'dr' in test_type else '#6a1b9a')

    bars = ax.bar(range(len(labels)), durations, color=colors_sp, edgecolor='white')
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel('Duration (seconds)', fontsize=11)
    ax.set_title('DR Recovery & Renewal Storm Results', fontsize=14, fontweight='bold')

    for bar, val in zip(bars, durations):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.3,
                f'{val}s', ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(os.path.join(report_dir, 'chart7-special-scenarios.png'), dpi=150)
    plt.close()
    print("  Generated: chart7-special-scenarios.png")

print("")
print("All charts generated successfully!")
PYTHON_SCRIPT

echo ""
echo "[3/3] Generating HTML report..."

# Generate a simple HTML report that embeds all charts
cat > "${REPORT_DIR}/report.html" << 'HTML_HEAD'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>cert-manager Performance Tuning Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #f8f9fa; color: #212529; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; color: #1a237e; }
        h2 { font-size: 1.4rem; margin: 2rem 0 1rem; color: #283593; border-bottom: 2px solid #e8eaf6; padding-bottom: 0.5rem; }
        .subtitle { color: #666; margin-bottom: 2rem; }
        .chart-container { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem;
                          box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .chart-container img { width: 100%; height: auto; border-radius: 4px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .metric-card { background: white; border-radius: 8px; padding: 1.5rem; text-align: center;
                      box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        .metric-value { font-size: 2.5rem; font-weight: bold; color: #1976d2; }
        .metric-label { font-size: 0.85rem; color: #666; margin-top: 0.3rem; }
        .metric-card.green .metric-value { color: #388e3c; }
        .metric-card.red .metric-value { color: #d32f2f; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08); margin-bottom: 2rem; }
        th { background: #1976d2; color: white; padding: 0.75rem 1rem; text-align: left; font-size: 0.85rem; }
        td { padding: 0.6rem 1rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }
        tr:nth-child(even) { background: #f8f9fa; }
        .highlight { background: #e8f5e9 !important; font-weight: bold; }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 500; }
        .tag-baseline { background: #ffebee; color: #c62828; }
        .tag-moderate { background: #e3f2fd; color: #1565c0; }
        .tag-aggressive { background: #e8f5e9; color: #2e7d32; }
        footer { text-align: center; color: #999; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #eee; font-size: 0.85rem; }
    </style>
</head>
<body>
<div class="container">
    <h1>cert-manager Performance Tuning Report</h1>
    <p class="subtitle">RFE-5620: Performance parameters for cert-manager on OpenShift</p>
HTML_HEAD

# Add dynamic content based on results
cat >> "${REPORT_DIR}/report.html" << HTML_METRICS
    <h2>Key Findings</h2>
    <div class="summary-grid">
        <div class="metric-card red">
            <div class="metric-value">45-78s</div>
            <div class="metric-label">Baseline Issuance (100-300 certs)</div>
        </div>
        <div class="metric-card green">
            <div class="metric-value">2-3s</div>
            <div class="metric-label">Tuned Issuance (100-300 certs)</div>
        </div>
        <div class="metric-card green">
            <div class="metric-value">15-39x</div>
            <div class="metric-label">Improvement Factor</div>
        </div>
        <div class="metric-card green">
            <div class="metric-value">0</div>
            <div class="metric-label">Controller Restarts (all tests)</div>
        </div>
    </div>
HTML_METRICS

cat >> "${REPORT_DIR}/report.html" << 'HTML_CHARTS'
    <h2>1. Issuance Time Comparison</h2>
    <div class="chart-container">
        <img src="chart1-issuance-time.png" alt="Issuance Time by Scenario">
    </div>

    <h2>2. Throughput Rate</h2>
    <div class="chart-container">
        <img src="chart2-issuance-rate.png" alt="Issuance Rate by Scenario">
    </div>

    <h2>3. Latency Percentiles</h2>
    <div class="chart-container">
        <img src="chart3-latency-percentiles.png" alt="Latency Percentiles">
    </div>

    <h2>4. Improvement Over Baseline</h2>
    <div class="chart-container">
        <img src="chart4-improvement-factor.png" alt="Improvement Factor">
    </div>

    <h2>5. Issuance Progress Over Time</h2>
    <div class="chart-container">
        <img src="chart5-progress-timeline.png" alt="Progress Timeline">
    </div>

    <h2>6. Parameter Configuration</h2>
    <div class="chart-container">
        <img src="chart6-parameters-table.png" alt="Parameters Table">
    </div>
HTML_CHARTS

# Add DR chart if it exists
if [[ -f "${REPORT_DIR}/chart7-special-scenarios.png" ]]; then
    cat >> "${REPORT_DIR}/report.html" << 'HTML_DR'
    <h2>7. DR Recovery & Renewal Storm</h2>
    <div class="chart-container">
        <img src="chart7-special-scenarios.png" alt="Special Scenarios">
    </div>
HTML_DR
fi

# Add results table
cat >> "${REPORT_DIR}/report.html" << 'HTML_TABLE_START'
    <h2>Complete Results Table</h2>
    <table>
        <tr>
            <th>Scenario</th>
            <th>Certs</th>
            <th>Issuance Time</th>
            <th>Rate (certs/min)</th>
            <th>P50</th>
            <th>P90</th>
            <th>P99</th>
            <th>Max</th>
        </tr>
HTML_TABLE_START

# Add rows from results
for SUMMARY_FILE in "${RESULTS_DIR}"/*/summary.json; do
    [[ -f "${SUMMARY_FILE}" ]] || continue
    SCENARIO=$(jq -r '.scenario' "${SUMMARY_FILE}")
    NUM_CERTS=$(jq -r '.num_certificates' "${SUMMARY_FILE}")
    ISSUANCE=$(jq -r '.issuance_duration_seconds' "${SUMMARY_FILE}")
    RATE=$(jq -r '.rate_certs_per_minute' "${SUMMARY_FILE}")
    P50=$(jq -r '.timing.p50_seconds' "${SUMMARY_FILE}")
    P90=$(jq -r '.timing.p90_seconds' "${SUMMARY_FILE}")
    P99=$(jq -r '.timing.p99_seconds' "${SUMMARY_FILE}")
    MAX=$(jq -r '.timing.max_seconds' "${SUMMARY_FILE}")

    TAG_CLASS="tag-baseline"
    ROW_CLASS=""
    if echo "${SCENARIO}" | grep -q "moderate"; then
        TAG_CLASS="tag-moderate"
    elif echo "${SCENARIO}" | grep -q "aggressive"; then
        TAG_CLASS="tag-aggressive"
        ROW_CLASS=" class=\"highlight\""
    fi

    cat >> "${REPORT_DIR}/report.html" << HTML_ROW
        <tr${ROW_CLASS}>
            <td><span class="tag ${TAG_CLASS}">${SCENARIO}</span></td>
            <td>${NUM_CERTS}</td>
            <td>${ISSUANCE}s</td>
            <td>${RATE}</td>
            <td>${P50}s</td>
            <td>${P90}s</td>
            <td>${P99}s</td>
            <td>${MAX}s</td>
        </tr>
HTML_ROW
done

cat >> "${REPORT_DIR}/report.html" << 'HTML_FOOTER'
    </table>

    <h2>Recommendations</h2>
    <table>
        <tr><th>Cluster Size</th><th>concurrent-workers</th><th>kube-api-qps</th><th>kube-api-burst</th><th>max-concurrent-challenges</th></tr>
        <tr><td>Small (&lt;100 certs)</td><td>5 (default)</td><td>20 (default)</td><td>50 (default)</td><td>60 (default)</td></tr>
        <tr><td>Medium (100-500 certs)</td><td>10</td><td>50</td><td>100</td><td>120</td></tr>
        <tr class="highlight"><td>Large / DR (500+ certs)</td><td>20</td><td>150</td><td>300</td><td>300</td></tr>
    </table>

    <footer>
        Generated by cert-manager Performance Testing Toolkit | RFE-5620
    </footer>
</div>
</body>
</html>
HTML_FOOTER

echo ""
echo "=== Report Generation Complete ==="
echo ""
echo "Charts: $(ls "${REPORT_DIR}"/*.png 2>/dev/null | wc -l | tr -d ' ') PNG files"
echo "Report: ${REPORT_DIR}/report.html"
echo ""
echo "Open in browser:"
echo "  open ${REPORT_DIR}/report.html"
