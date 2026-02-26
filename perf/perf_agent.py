import os
import re
import json
from datetime import datetime

PATTERNS = {
    "Timers/Animation": r"setInterval|setTimeout|requestAnimationFrame|requestIdleCallback",
    "Concurrency": r"Promise\.allSettled|Promise\.all|Promise\.any|Promise\.race",
    "Workers": r"new Worker|Worker\(|postMessage\(|getDmDecryptWorkerQueueSize|decryptDmInWorker",
    "WebTorrent": r"new WebTorrent|WebTorrent|torrent|magnet|torrentHash|magnetValidators",
    "Nostr/Relays": r"integrationClient\.pool|publishEventToRelays|pool\.list|queueSignEvent|relayManager|authService|hydrateFromStorage",
    "Visibility": r"document\.hidden|visibilitychange",
}


def search_files(directory):
    hits = []
    for root, dirs, files in os.walk(directory):
        if "node_modules" in dirs:
            dirs.remove("node_modules")
        if ".git" in dirs:
            dirs.remove(".git")

        for file in files:
            if not file.endswith((".js", ".ts", ".mjs", ".jsx", ".tsx", ".py")):
                continue

            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        for category, pattern in PATTERNS.items():
                            if re.search(pattern, line):
                                hits.append(
                                    {
                                        "file": filepath,
                                        "line": i + 1,
                                        "category": category,
                                        "snippet": line.strip(),
                                    }
                                )
            except Exception as e:
                print(f"Error reading {filepath}: {e}")
    return hits


def main():
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")
    date_str = datetime.utcnow().strftime("%Y-%m-%d")

    print("Running Perf Agent Search...")
    hits = search_files("src")  # Assuming source is in src/

    # Also search torch/src if needed? The prompt says "Repo: this repository".
    # Assuming 'src' is the main code.

    # Save hits
    hits_file = f"reports/performance/hits-{date_str}.json"
    with open(hits_file, "w") as f:
        json.dump(hits, f, indent=2)
    print(f"Hits saved to {hits_file}")

    # Generate Daily Report
    report_file = f"reports/performance/daily-perf-report-{date_str}.md"

    report_content = f"""# Daily Performance Report - {date_str}

## Summary
Found {len(hits)} performance-relevant code patterns.

## Findings by Category
"""

    categories = {}
    for hit in hits:
        cat = hit["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(hit)

    for cat, items in categories.items():
        report_content += f"\n### {cat} ({len(items)} hits)\n"
        for item in items[:5]:  # Limit to 5 examples
            report_content += (
                f"- `{item['file']}:{item['line']}`: `{item['snippet']}`\n"
            )
        if len(items) > 5:
            report_content += f"- ... and {len(items)-5} more.\n"

    report_content += """
## Metrics
- Login Time: N/A (Baseline)
- Decrypt Queue: N/A (Baseline)

## Actions Taken
- Initialized baseline reporting.
- Ran pattern search.

## Blockers
- None.
"""

    with open(report_file, "w") as f:
        f.write(report_content)
    print(f"Report saved to {report_file}")

    # Create Context File
    context_file = f"src/context/CONTEXT_{timestamp}.md"
    context_content = f"""# Performance Agent Run {timestamp}

## Goal
Daily measurable improvement of app responsiveness.

## Scope
- Search for expensive patterns.
- Establish baseline.

## Assumptions
- Codebase is in `src/`.

## DoD
- Report generated.
- Hits cataloged.
"""
    with open(context_file, "w") as f:
        f.write(context_content)
    print(f"Context saved to {context_file}")

    # Create Initial Baseline if not exists
    baseline_file = "reports/performance/INITIAL_BASELINE.md"
    if not os.path.exists(baseline_file):
        with open(baseline_file, "w") as f:
            f.write("# Initial Performance Baseline\n\nNo historical data available.\n")
        print(f"Baseline saved to {baseline_file}")


if __name__ == "__main__":
    main()
