# Binary Analyser Plugin for Binary Ninja

## Overview

Binary Analyser is a comprehensive Binary Ninja plugin that provides in-depth analysis and visualisation of binary files and directories. The plugin extracts key metrics, identifies dangerous function calls, and generates interactive dashboards to help security researchers and reverse engineers quickly assess binaries.

## Features

- **Comprehensive Binary Analysis**:
  - Extract binary metadata (architecture, endianness)
  - Calculate SHA256 hash for each binary
  - Compute cyclomatic complexity for all functions
  - Calculate Shannon entropy of binary data
  - Identify calls to dangerous functions (system, execve, etc.)
  - Extract segments information
  - Count functions and strings

- **Batch Analysis**:
  - Analyse individual binaries or entire directories
  - Compare metrics across multiple binaries
  - Process and visualize results in a unified dashboard

- **Interactive Visualization**:
  - HTML dashboard with interactive charts
  - Entropy comparison charts and tables
  - Cyclomatic complexity visualization
  - Dangerous function reference analysis
  - Color-coded risk assessment

- **Export Options**:
  - Export results to CSV for further analysis
  - Generate comprehensive HTML reports
  - Open dashboards directly in browser

## Installation

### Prerequisites
- Binary Ninja 4.0 >
- Python 3.10 >

### Installation Steps

1. Clone the repo `git clone https://github.com/meerkatone/Binary-Analyser-Plugin-for-Binary-Ninja.git`

2. Place the `binary_analyser_plugin.py` file in your Binary Ninja plugins directory:
   - Windows: `%APPDATA%\Binary Ninja\plugins`
   - Linux: `~/.binaryninja/plugins`
   - MacOS: `~/Library/Application Support/Binary Ninja/plugins`

3. Restart Binary Ninja or reload plugins

4. Verify installation by checking that "Binary Analyser" appears in the plugins menu

## Usage

### Set Output Directory

Before using the plugin, set the output directory where analysis results will be saved:

1. Select `Plugins > Binary Analyser > Set Output Directory`
2. Choose a directory for saving results

### Analyse Current Binary

To analyse the currently loaded binary:

1. Open a binary file in Binary Ninja
2. Select `Plugins > Binary Analyser > Analyse Current Binary`
3. Wait for analysis to complete
4. View the summary dialog and choose whether to open the dashboard

### Analyse Directory

To analyse all binaries in a directory:

1. Select `Plugins > Binary Analyser > Analyse Directory`
2. Choose a directory containing binaries to analyse
3. Wait for the analysis to complete
4. View the summary and open the generated dashboard

### Understanding the Dashboard

The generated dashboard provides:

- **Summary metrics** across all analysed binaries
- **Binary comparison charts** for entropy, cyclomatic complexity, and dangerous function references
- **Detailed tables** with risk classifications and metrics
- **Per-binary details** including segments, strings, and dangerous function references

#### Risk Classification

The plugin uses the following risk classification system:

| Metric | Low | Medium | High/Critical |
|--------|-----|--------|---------------|
| Entropy | < 6.0 | 6.0 - 7.0 | > 7.0 |
| Cyclomatic Complexity | < 10 | 10 - 15 | > 15 |
| Dangerous Function Refs | 0 | 1 - 5 | > 5 (High), > 10 (Critical) |

