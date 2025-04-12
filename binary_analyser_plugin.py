import os
import math
import csv
import time
import tempfile
import webbrowser
from datetime import datetime
from pathlib import Path

import binaryninja
from binaryninja import PluginCommand, BinaryView, interaction
from binaryninja.settings import Settings
from binaryninja.log import log_info, log_error

# Initialize settings
Settings().register_setting("binaryanalyser.output_dir", """
    {
        "title" : "Output Directory",
        "type" : "string",
        "default" : "",
        "description" : "Directory where analysis results will be saved"
    }
""")

# List of dangerous functions to check for
DANGEROUS_FUNCTIONS = ["system", "execve", "execle", "execvp", "execlp", "doSystemCmd"]

class BinaryAnalyser:
    def __init__(self):
        self.results = []
        self.output_dir = Settings().get_string("binaryanalyser.output_dir")
        if not self.output_dir:
            self.output_dir = os.path.expanduser("~")

    def get_file_name(self, path):
        """Get the name of the binary file"""
        return os.path.basename(path)

    def get_architecture(self, bv):
        """Get the binary architecture"""
        return bv.arch.name

    def get_endianness(self, bv):
        """Get the binary endianness"""
        return "Little" if bv.endianness == binaryninja.Endianness.LittleEndian else "Big"

    def get_hash(self, bv):
        """Calculate the SHA256 hash of the binary"""
        t = binaryninja.transform.Transform["SHA256"]
        p = bv.parent_view
        h = t.encode(p.read(p.start, p.length))
        return h.hex()

    def calculate_cyclomatic_complexity(self, function):
        """Calculate the cyclomatic complexity of a function"""
        edges = sum([len(block.outgoing_edges) for block in function.basic_blocks])
        nodes = len(function.basic_blocks)
        return edges - nodes + 2

    def calculate_entropy(self, data):
        """Calculate the entropy of the binary data"""
        ent = 0
        if not data:
            return 0

        for byte in range(256):
            p_x = float(data.count(bytes([byte]))) / len(data)
            if p_x > 0:
                ent += -p_x * math.log(p_x, 2)
        return ent

    def get_segments(self, bv):
        """Get the segments of the binary"""
        segment_info = []
        for seg in bv.segments:
            segment_info.append({
                "start": hex(seg.start),
                "end": hex(seg.end),
                "readable": seg.readable,
                "writable": seg.writable,
                "executable": seg.executable,
            })
        return segment_info

    def find_xrefs_to_dangerous_functions(self, bv):
        """Find cross-references to dangerous functions"""
        xref_info = []
        for func_name in DANGEROUS_FUNCTIONS:
            symbol = bv.get_symbol_by_raw_name(func_name)
            if symbol:
                xrefs = bv.get_code_refs(symbol.address)
                for xref in xrefs:
                    xref_info.append({
                        "function": func_name,
                        "caller_func": hex(xref.function.start),
                        "addr": hex(xref.address)
                    })
        return xref_info

    def analyze_binary(self, bv):
        """Analyse a single binary"""
        start_time = time.time()

        # Extract basic information
        filepath = bv.file.filename
        filename = self.get_file_name(filepath)
        file_hash = self.get_hash(bv)
        architecture = self.get_architecture(bv)
        endianness = self.get_endianness(bv)

        # Calculate cyclomatic complexity
        ccs = []
        for function in bv.functions:
            cc = self.calculate_cyclomatic_complexity(function)
            ccs.append(cc)
        avg_cc = sum(ccs) / len(ccs) if ccs else 0

        # Get functions list
        funcs = [(func.name, hex(func.start)) for func in bv.functions]

        # Get strings
        strings = [(str(string), hex(string.start)) for string in bv.get_strings()]

        # Get segments information
        segment_info = self.get_segments(bv)

        # Find references to dangerous functions
        getrefs = self.find_xrefs_to_dangerous_functions(bv)

        # Calculate entropy
        data = bv.read(bv.start, bv.length)
        entropy = self.calculate_entropy(data)

        # Execution time
        execution_time = time.time() - start_time

        # Compile results
        result = {
            "Binary": filename,
            "File_Hash": file_hash,
            "Architecture": architecture,
            "Endianness": endianness,
            "Average_Cyclomatic_Complexity": avg_cc,
            "Entropy": entropy,
            "Functions_Count": len(funcs),
            "Strings_Count": len(strings),
            "Segments_Count": len(segment_info),
            "Dangerous_Func_Refs": len(getrefs),
            "Execution_Time": execution_time,
            "Analysis_Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Functions": funcs,
            "Strings": strings,
            "Segments": segment_info,
            "Xrefs_to_Dangerous": getrefs
        }

        self.results.append(result)
        return result

    def save_results_to_csv(self):
        """Save analysis results to CSV file"""
        if not self.results:
            log_error("No results to save")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = os.path.join(self.output_dir, f"binary_analysis_{timestamp}.csv")

        try:
            with open(csv_file, 'w', newline='') as f:
                # Extract basic fields for CSV
                fieldnames = [
                    "Binary", "File_Hash", "Architecture", "Endianness",
                    "Average_Cyclomatic_Complexity", "Entropy", "Functions_Count",
                    "Strings_Count", "Segments_Count", "Dangerous_Func_Refs",
                    "Execution_Time", "Analysis_Date"
                ]

                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for result in self.results:
                    # Create a simplified version with just the basic fields
                    row = {field: result[field] for field in fieldnames}
                    writer.writerow(row)

            log_info(f"Results saved to {csv_file}")
            return csv_file
        except Exception as e:
            log_error(f"Failed to save results: {str(e)}")
            return None

    def generate_dashboard(self):
        """Generate an HTML dashboard with the analysis results"""
        if not self.results:
            log_error("No results to generate dashboard")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = os.path.join(self.output_dir, f"binary_analysis_dashboard_{timestamp}.html")

        try:
            with open(html_file, 'w') as f:
                f.write("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Binary Analysis Dashboard</title>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.1/chart.min.js"></script>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            margin: 0;
                            padding: 20px;
                            color: #333;
                        }
                        h1, h2, h3 {
                            color: #2c3e50;
                        }
                        table {
                            border-collapse: collapse;
                            width: 100%;
                            margin-bottom: 20px;
                        }
                        th, td {
                            border: 1px solid #ddd;
                            padding: 8px;
                            text-align: left;
                        }
                        th {
                            background-color: #f2f2f2;
                            font-weight: bold;
                        }
                        tr:nth-child(even) {
                            background-color: #f9f9f9;
                        }
                        .dashboard-section {
                            margin-bottom: 30px;
                            border: 1px solid #ddd;
                            padding: 15px;
                            border-radius: 5px;
                        }
                        .chart-container {
                            width: 100%;
                            height: 400px;
                            margin-bottom: 30px;
                        }
                        .binary-details {
                            margin-bottom: 40px;
                            padding-bottom: 20px;
                            border-bottom: 2px solid #eee;
                        }
                        .warning {
                            color: #e74c3c;
                            font-weight: bold;
                        }
                        .metric-container {
                            display: flex;
                            flex-wrap: wrap;
                            gap: 20px;
                            margin-bottom: 20px;
                        }
                        .metric-box {
                            background-color: #f8f9fa;
                            border-radius: 5px;
                            padding: 15px;
                            flex: 1;
                            min-width: 200px;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }
                        .metric-title {
                            font-size: 0.9em;
                            color: #7f8c8d;
                            margin-bottom: 5px;
                        }
                        .metric-value {
                            font-size: 1.8em;
                            font-weight: bold;
                            color: #2c3e50;
                        }
                        .high-entropy {
                            color: #e74c3c;
                        }
                        .medium-entropy {
                            color: #f39c12;
                        }
                        .low-entropy {
                            color: #27ae60;
                        }
                        .chart-row {
                            display: flex;
                            flex-wrap: wrap;
                            gap: 20px;
                            margin-bottom: 20px;
                        }
                        .chart-column {
                            flex: 1;
                            min-width: 300px;
                        }
                        .comparison-table {
                            margin-top: 30px;
                            margin-bottom: 30px;
                        }
                        .comparison-table th {
                            position: sticky;
                            top: 0;
                            background-color: #f2f2f2;
                        }
                    </style>
                </head>
                <body>
                    <h1>Binary Analysis Dashboard</h1>
                    <p>Analysis performed on: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                """)

                # Summary section
                f.write("""
                    <div class="dashboard-section">
                        <h2>Summary</h2>
                        <div class="metric-container">
                            <div class="metric-box">
                                <div class="metric-title">Binaries Analysed</div>
                                <div class="metric-value">""" + str(len(self.results)) + """</div>
                            </div>
                """)

                # Calculate average metrics across all binaries
                avg_entropy = sum(r["Entropy"] for r in self.results) / len(self.results)
                avg_cc = sum(r["Average_Cyclomatic_Complexity"] for r in self.results) / len(self.results)
                total_dangerous_refs = sum(r["Dangerous_Func_Refs"] for r in self.results)

                f.write("""
                            <div class="metric-box">
                                <div class="metric-title">Avg. Entropy</div>
                                <div class="metric-value">""" + f"{avg_entropy:.2f}" + """</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-title">Avg. Cyclomatic Complexity</div>
                                <div class="metric-value">""" + f"{avg_cc:.2f}" + """</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-title">Dangerous Function Refs</div>
                                <div class="metric-value">""" + str(total_dangerous_refs) + """</div>
                            </div>
                        </div>
                    </div>
                """)

                # Add comparison charts for entropy, cyclomatic complexity, and dangerous functions
                if len(self.results) > 1:  # Only show charts if we have multiple binaries
                    binary_names = [r["Binary"] for r in self.results]
                    entropy_values = [r["Entropy"] for r in self.results]
                    cc_values = [r["Average_Cyclomatic_Complexity"] for r in self.results]
                    dangerous_refs = [r["Dangerous_Func_Refs"] for r in self.results]

                    # Generate colors for the charts
                    entropy_colors = []
                    for entropy in entropy_values:
                        if entropy > 7.0:
                            entropy_colors.append('rgba(231, 76, 60, 0.7)')  # Red for high entropy
                        elif entropy > 6.0:
                            entropy_colors.append('rgba(243, 156, 18, 0.7)')  # Orange for medium entropy
                        else:
                            entropy_colors.append('rgba(39, 174, 96, 0.7)')  # Green for low entropy

                    # Generate colors for dangerous functions
                    danger_colors = []
                    for count in dangerous_refs:
                        if count > 10:
                            danger_colors.append('rgba(192, 57, 43, 0.7)')  # Dark red for high count
                        elif count > 5:
                            danger_colors.append('rgba(231, 76, 60, 0.7)')  # Red for medium count
                        elif count > 0:
                            danger_colors.append('rgba(243, 156, 18, 0.7)')  # Orange for low count
                        else:
                            danger_colors.append('rgba(39, 174, 96, 0.7)')  # Green for no dangerous functions

                    f.write("""
                    <div class="dashboard-section">
                        <h2>Binary Comparisons</h2>
                        <div class="chart-row">
                            <div class="chart-column">
                                <h3>Entropy Comparison</h3>
                                <div class="chart-container">
                                    <canvas id="entropyChart"></canvas>
                                </div>
                            </div>
                            <div class="chart-column">
                                <h3>Cyclomatic Complexity Comparison</h3>
                                <div class="chart-container">
                                    <canvas id="complexityChart"></canvas>
                                </div>
                            </div>
                        </div>

                        <div class="chart-row">
                            <div class="chart-column">
                                <h3>Dangerous Function References</h3>
                                <div class="chart-container">
                                    <canvas id="dangerousChart"></canvas>
                                </div>
                            </div>
                        </div>

                        <h3>Entropy Comparison Table</h3>
                        <div class="comparison-table">
                            <table>
                                <tr>
                                    <th>Binary</th>
                                    <th>Entropy</th>
                                    <th>Classification</th>
                                </tr>
                    """)

                    # Entropy comparison table
                    sorted_entropy = sorted(zip(binary_names, entropy_values), key=lambda x: x[1], reverse=True)
                    for binary, entropy in sorted_entropy:
                        entropy_class = ""
                        classification = ""
                        if entropy > 7.0:
                            entropy_class = "high-entropy"
                            classification = "High (Potential packed/encrypted content)"
                        elif entropy > 6.0:
                            entropy_class = "medium-entropy"
                            classification = "Medium"
                        else:
                            entropy_class = "low-entropy"
                            classification = "Low"

                        f.write(f"""
                                <tr>
                                    <td>{binary}</td>
                                    <td class="{entropy_class}">{entropy:.4f}</td>
                                    <td>{classification}</td>
                                </tr>
                        """)

                    f.write("""
                            </table>
                        </div>

                        <h3>Cyclomatic Complexity Comparison Table</h3>
                        <div class="comparison-table">
                            <table>
                                <tr>
                                    <th>Binary</th>
                                    <th>Avg. Cyclomatic Complexity</th>
                                    <th>Classification</th>
                                </tr>
                    """)

                    # CC comparison table
                    sorted_cc = sorted(zip(binary_names, cc_values), key=lambda x: x[1], reverse=True)
                    for binary, cc in sorted_cc:
                        cc_class = ""
                        classification = ""
                        if cc > 15:
                            cc_class = "high-entropy" # Reusing style
                            classification = "High (Very complex code)"
                        elif cc > 10:
                            cc_class = "medium-entropy" # Reusing style
                            classification = "Medium (Moderately complex)"
                        else:
                            cc_class = "low-entropy" # Reusing style
                            classification = "Low (Simple code)"

                        f.write(f"""
                                <tr>
                                    <td>{binary}</td>
                                    <td class="{cc_class}">{cc:.4f}</td>
                                    <td>{classification}</td>
                                </tr>
                        """)

                    f.write("""
                            </table>
                        </div>

                        <h3>Dangerous Function References Table</h3>
                        <div class="comparison-table">
                            <table>
                                <tr>
                                    <th>Binary</th>
                                    <th>Dangerous Function References</th>
                                    <th>Risk Level</th>
                                </tr>
                    """)

                    # Dangerous function references table
                    sorted_danger = sorted(zip(binary_names, dangerous_refs), key=lambda x: x[1], reverse=True)
                    for binary, count in sorted_danger:
                        danger_class = ""
                        risk_level = ""
                        if count > 10:
                            danger_class = "high-entropy" # Reusing style
                            risk_level = "Critical (Numerous potentially unsafe calls)"
                        elif count > 5:
                            danger_class = "high-entropy" # Reusing style
                            risk_level = "High (Multiple potentially unsafe calls)"
                        elif count > 0:
                            danger_class = "medium-entropy" # Reusing style
                            risk_level = "Medium (Some potentially unsafe calls)"
                        else:
                            danger_class = "low-entropy" # Reusing style
                            risk_level = "Low (No dangerous function calls detected)"

                        f.write(f"""
                                <tr>
                                    <td>{binary}</td>
                                    <td class="{danger_class}">{count}</td>
                                    <td>{risk_level}</td>
                                </tr>
                        """)

                    f.write("""
                            </table>
                        </div>
                    </div>

                    <script>
                    // Entropy Chart
                    const entropyCtx = document.getElementById('entropyChart').getContext('2d');
                    const entropyChart = new Chart(entropyCtx, {
                        type: 'bar',
                        data: {
                            labels: """ + str(binary_names).replace("'", '"') + """,
                            datasets: [{
                                label: 'Entropy (bits)',
                                data: """ + str(entropy_values) + """,
                                backgroundColor: """ + str(entropy_colors).replace("'", '"') + """,
                                borderColor: 'rgba(0, 0, 0, 0.2)',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    display: false
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            let value = context.raw;
                                            let classification = '';
                                            if (value > 7.0) {
                                                classification = '(High - Potential encrypted/packed)';
                                            } else if (value > 6.0) {
                                                classification = '(Medium)';
                                            } else {
                                                classification = '(Low)';
                                            }
                                            return `Entropy: ${value.toFixed(4)} ${classification}`;
                                        }
                                    }
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: false,
                                    min: Math.min(...""" + str(entropy_values) + """) * 0.9,
                                    max: Math.max(8, Math.max(...""" + str(entropy_values) + """) * 1.05),
                                    title: {
                                        display: true,
                                        text: 'Entropy (bits)'
                                    }
                                },
                                x: {
                                    title: {
                                        display: true,
                                        text: 'Binary'
                                    }
                                }
                            }
                        }
                    });

                    // Cyclomatic Complexity Chart
                    const ccCtx = document.getElementById('complexityChart').getContext('2d');
                    const ccChart = new Chart(ccCtx, {
                        type: 'bar',
                        data: {
                            labels: """ + str(binary_names).replace("'", '"') + """,
                            datasets: [{
                                label: 'Avg. Cyclomatic Complexity',
                                data: """ + str(cc_values) + """,
                                backgroundColor: 'rgba(52, 152, 219, 0.7)',
                                borderColor: 'rgba(0, 0, 0, 0.2)',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    display: false
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            let value = context.raw;
                                            let classification = '';
                                            if (value > 15) {
                                                classification = '(High complexity)';
                                            } else if (value > 10) {
                                                classification = '(Medium complexity)';
                                            } else {
                                                classification = '(Low complexity)';
                                            }
                                            return `Complexity: ${value.toFixed(2)} ${classification}`;
                                        }
                                    }
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: false,
                                    min: 0,
                                    title: {
                                        display: true,
                                        text: 'Cyclomatic Complexity'
                                    }
                                },
                                x: {
                                    title: {
                                        display: true,
                                        text: 'Binary'
                                    }
                                }
                            }
                        }
                    });

                    // Dangerous Function References Chart
                    const dangerCtx = document.getElementById('dangerousChart').getContext('2d');

                    // Sort data by dangerous reference count (descending)
                    const dangerData = [];
                    const sortedDangerLabels = [];
                    const sortedDangerColors = [];

                    // Create array of [binary_name, dangerous_count, color] for sorting
                    const dangerSortData = [];
                    for (let i = 0; i < """ + str(len(binary_names)) + """; i++) {
                        dangerSortData.push({
                            name: """ + str(binary_names).replace("'", '"') + """[i],
                            value: """ + str(dangerous_refs) + """[i],
                            color: """ + str(danger_colors).replace("'", '"') + """[i]
                        });
                    }

                    // Sort by value (descending)
                    dangerSortData.sort((a, b) => b.value - a.value);

                    // Create new arrays in sorted order
                    dangerSortData.forEach(item => {
                        sortedDangerLabels.push(item.name);
                        dangerData.push(item.value);
                        sortedDangerColors.push(item.color);
                    });

                    const dangerChart = new Chart(dangerCtx, {
                        type: 'bar',
                        data: {
                            labels: sortedDangerLabels,
                            datasets: [{
                                label: 'Dangerous Function References',
                                data: dangerData,
                                backgroundColor: sortedDangerColors,
                                borderColor: 'rgba(0, 0, 0, 0.2)',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    display: false
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            let value = context.raw;
                                            let risk = '';
                                            if (value > 10) {
                                                risk = '(Critical risk)';
                                            } else if (value > 5) {
                                                risk = '(High risk)';
                                            } else if (value > 0) {
                                                risk = '(Medium risk)';
                                            } else {
                                                risk = '(Low risk)';
                                            }
                                            return `References: ${value} ${risk}`;
                                        }
                                    }
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    title: {
                                        display: true,
                                        text: 'Number of References'
                                    }
                                },
                                x: {
                                    title: {
                                        display: true,
                                        text: 'Binary'
                                    }
                                }
                            }
                        }
                    });
                    </script>
                    """)

                # Overview table
                f.write("""
                    <div class="dashboard-section">
                        <h2>Binaries Overview</h2>
                        <table>
                            <tr>
                                <th>Binary</th>
                                <th>Architecture</th>
                                <th>Endianness</th>
                                <th>Entropy</th>
                                <th>Avg. CC</th>
                                <th>Functions</th>
                                <th>Strings</th>
                                <th>Dangerous Refs</th>
                            </tr>
                """)

                for result in self.results:
                    entropy_class = ""
                    if result["Entropy"] > 7.0:
                        entropy_class = "high-entropy"
                    elif result["Entropy"] > 6.0:
                        entropy_class = "medium-entropy"
                    else:
                        entropy_class = "low-entropy"

                    f.write(f"""
                            <tr>
                                <td>{result["Binary"]}</td>
                                <td>{result["Architecture"]}</td>
                                <td>{result["Endianness"]}</td>
                                <td class="{entropy_class}">{result["Entropy"]:.2f}</td>
                                <td>{result["Average_Cyclomatic_Complexity"]:.2f}</td>
                                <td>{result["Functions_Count"]}</td>
                                <td>{result["Strings_Count"]}</td>
                                <td>{result["Dangerous_Func_Refs"]}</td>
                            </tr>
                    """)

                f.write("""
                        </table>
                    </div>
                """)

                # Detailed information for each binary
                for i, result in enumerate(self.results):
                    f.write(f"""
                    <div class="binary-details">
                        <h2>{i+1}. {result["Binary"]}</h2>
                        <div class="metric-container">
                            <div class="metric-box">
                                <div class="metric-title">Architecture</div>
                                <div class="metric-value">{result["Architecture"]}</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-title">Endianness</div>
                                <div class="metric-value">{result["Endianness"]}</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-title">Entropy</div>
                                <div class="metric-value">{result["Entropy"]:.2f}</div>
                            </div>
                            <div class="metric-box">
                                <div class="metric-title">Cyclomatic Complexity</div>
                                <div class="metric-value">{result["Average_Cyclomatic_Complexity"]:.2f}</div>
                            </div>
                        </div>

                        <h3>File Hash</h3>
                        <p><code>{result["File_Hash"]}</code></p>
                    """)

                    # Show dangerous function references if any
                    if result["Xrefs_to_Dangerous"]:
                        f.write("""
                        <div class="dashboard-section">
                            <h3>Dangerous Function References</h3>
                            <table>
                                <tr>
                                    <th>Function</th>
                                    <th>Caller Function</th>
                                    <th>Address</th>
                                </tr>
                        """)

                        for ref in result["Xrefs_to_Dangerous"]:
                            f.write(f"""
                                <tr>
                                    <td class="warning">{ref["function"]}</td>
                                    <td>{ref["caller_func"]}</td>
                                    <td>{ref["addr"]}</td>
                                </tr>
                            """)

                        f.write("""
                            </table>
                        </div>
                        """)

                    # Show segments
                    f.write("""
                    <div class="dashboard-section">
                        <h3>Segments</h3>
                        <table>
                            <tr>
                                <th>Start</th>
                                <th>End</th>
                                <th>Readable</th>
                                <th>Writable</th>
                                <th>Executable</th>
                            </tr>
                    """)

                    for seg in result["Segments"]:
                        f.write(f"""
                            <tr>
                                <td>{seg["start"]}</td>
                                <td>{seg["end"]}</td>
                                <td>{"Yes" if seg["readable"] else "No"}</td>
                                <td>{"Yes" if seg["writable"] else "No"}</td>
                                <td>{"Yes" if seg["executable"] else "No"}</td>
                            </tr>
                        """)

                    f.write("""
                        </table>
                    </div>
                    """)

                    f.write("</div>") # Close binary-details

                f.write("""
                </body>
                </html>
                """)

            log_info(f"Dashboard saved to {html_file}")
            return html_file
        except Exception as e:
            log_error(f"Failed to generate dashboard: {str(e)}")
            return None


def set_output_directory(bv):
    """Set the output directory for analysis results"""
    directory = interaction.get_directory_name_input("Select Output Directory")
    if directory:
        Settings().set_string("binaryanalyser.output_dir", directory)
        interaction.show_message_box(
            "Binary Analyser",
            f"Output directory set to: {directory}"
        )


def analyze_current_binary(bv):
    """Analyse the currently open binary"""
    analyser = BinaryAnalyser()

    try:
        interaction.show_message_box(
            "Binary Analyser",
            "Starting analysis of current binary..."
        )

        result = analyser.analyze_binary(bv)
        csv_file = analyser.save_results_to_csv()
        html_file = analyser.generate_dashboard()

        summary = f"""
        Analysis completed!

        Binary: {result['Binary']}
        Architecture: {result['Architecture']}
        Entropy: {result['Entropy']:.2f}
        Average Cyclomatic Complexity: {result['Average_Cyclomatic_Complexity']:.2f}
        Functions: {result['Functions_Count']}
        Dangerous Function References: {result['Dangerous_Func_Refs']}

        Results saved to: {csv_file}
        Dashboard saved to: {html_file}
        """

        interaction.show_message_box("Analysis Results", summary)

        # Ask if user wants to open the dashboard
        if html_file and interaction.show_message_box(
            "Open Dashboard?",
            "Would you like to open the dashboard in your browser?",
            buttons=interaction.MessageBoxButtonSet.YesNoButtonSet
        ) == interaction.MessageBoxButtonResult.YesButton:
            webbrowser.open(f"file://{html_file}")

    except Exception as e:
        interaction.show_message_box(
            "Error",
            f"An error occurred during analysis: {str(e)}"
        )


def analyze_directory(bv):
    """Analyse all binaries in a directory"""
    analyser = BinaryAnalyser()

    # Get directory to analyze
    directory = interaction.get_directory_name_input("Select Directory with Binaries")
    if not directory:
        return

    try:
        # Find all files in the directory
        binaries = [
            os.path.join(directory, f)
            for f in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, f))
        ]

        if not binaries:
            interaction.show_message_box(
                "Binary Analyser",
                "No files found in the selected directory."
            )
            return

        interaction.show_message_box(
            "Binary Analyser",
            f"Starting analysis of {len(binaries)} files in {directory}..."
        )

        # Analyse each file
        successful = 0
        for binary_path in binaries:
            try:
                # Try to load the binary
                with binaryninja.load(binary_path) as binary_view:
                    if binary_view:
                        analyser.analyze_binary(binary_view)
                        successful += 1
                    else:
                        log_error(f"Failed to load {binary_path}")
            except Exception as e:
                log_error(f"Error analyzing {binary_path}: {str(e)}")

        # Save results and generate dashboard
        if successful > 0:
            csv_file = analyser.save_results_to_csv()
            html_file = analyser.generate_dashboard()

            summary = f"""
            Analysis completed!

            Successfully analyzed: {successful}/{len(binaries)} files
            Results saved to: {csv_file}
            Dashboard saved to: {html_file}
            """

            interaction.show_message_box("Analysis Results", summary)

            # Ask if user wants to open the dashboard
            if html_file and interaction.show_message_box(
                "Open Dashboard?",
                "Would you like to open the dashboard in your browser?",
                buttons=interaction.MessageBoxButtonSet.YesNoButtonSet
            ) == interaction.MessageBoxButtonResult.YesButton:
                webbrowser.open(f"file://{html_file}")
        else:
            interaction.show_message_box(
                "Binary Analyser",
                "No files were successfully analyzed."
            )

    except Exception as e:
        interaction.show_message_box(
            "Error",
            f"An error occurred during analysis: {str(e)}"
        )


# Register plugin commands
PluginCommand.register(
    "Binary Analyser\\Set Output Directory",
    "Set the directory where analysis results will be saved",
    set_output_directory
)

PluginCommand.register(
    "Binary Analyser\\Analyse Current Binary",
    "Analyse the currently loaded binary",
    analyze_current_binary
)

PluginCommand.register(
    "Binary Analyser\\Analyse Directory",
    "Analyse all binaries in a directory",
    analyze_directory
)
