# utils/reporter.py

import os
from datetime import datetime

REPORT_HTML = "output/report.html"
REPORT_CSS = "output/styles.css"
REPORT_JS = "output/script.js"

def init_html_report():
    os.makedirs("output", exist_ok=True)
    
    # Create CSS file
    if not os.path.exists(REPORT_CSS):
        with open(REPORT_CSS, "w", encoding="utf-8") as f:
            f.write("""body { 
    font-family: monospace; 
    background: #111; 
    color: #eee; 
    padding: 20px; 
}

h1, h2 { 
    color: #0ff; 
}

.block { 
    border-top: 1px solid #444; 
    margin-top: 20px; 
    padding-top: 10px; 
}

.timestamp { 
    color: #888; 
    font-size: 0.9em; 
}

.section-title { 
    color: #ff0; 
    margin-bottom: 5px; 
}

pre { 
    background: #222; 
    padding: 10px; 
    border-radius: 6px; 
    overflow-x: auto; 
}

.filters { 
    margin: 20px 0; 
}

.filters button {
    background: #222; 
    color: #0ff; 
    border: 1px solid #0ff;
    padding: 5px 10px; 
    margin-right: 10px; 
    cursor: pointer;
}

.filters button.active { 
    background: #0ff; 
    color: #000; 
}

.live-dot {
    width: 10px; 
    height: 10px; 
    background: lime; 
    border-radius: 50%;
    display: inline-block; 
    margin-left: 10px; 
    animation: blink 1s infinite;
}

@keyframes blink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.2; }
}

#content-container {
    display: flex;
    flex-direction: column;
}

.debug-info {
    background: #333;
    padding: 10px;
    margin: 10px 0;
    border-radius: 5px;
    font-size: 0.8em;
    color: #ccc;
}""")

    # Create JavaScript file
    if not os.path.exists(REPORT_JS):
        with open(REPORT_JS, "w", encoding="utf-8") as f:
            f.write("""let currentFilter = null;

function filter(event, module) {
    console.log('Filtering by:', module);
    currentFilter = module;
    
    const blocks = document.querySelectorAll('.block');
    console.log('Total blocks found:', blocks.length);
    
    let visibleCount = 0;
    blocks.forEach(b => {
        const blockModule = b.getAttribute('data-module');
        console.log('Block module:', blockModule, 'Looking for:', module);
        
        if (blockModule === module) {
            b.style.display = 'block';
            visibleCount++;
        } else {
            b.style.display = 'none';
        }
    });
    
    console.log('Visible blocks after filter:', visibleCount);
    
    // Update debug info
    updateDebugInfo();
    
    // Update button states
    document.querySelectorAll('.filters button').forEach(btn => btn.classList.remove('active'));
    event.currentTarget.classList.add('active');
}

function showAll(event) {
    console.log('Showing all blocks');
    currentFilter = null;
    
    document.querySelectorAll('.block').forEach(b => {
        b.style.display = 'block';
    });
    
    updateDebugInfo();
    
    document.querySelectorAll('.filters button').forEach(btn => btn.classList.remove('active'));
    event.currentTarget.classList.add('active');
}

function updateDebugInfo() {
    const debugDiv = document.getElementById('debug-info');
    if (!debugDiv) return;
    
    const blocks = document.querySelectorAll('.block');
    const visibleBlocks = document.querySelectorAll('.block[style*="block"], .block:not([style*="none"])');
    
    let moduleInfo = {};
    blocks.forEach(b => {
        const module = b.getAttribute('data-module');
        if (!moduleInfo[module]) moduleInfo[module] = 0;
        moduleInfo[module]++;
    });
    
    debugDiv.innerHTML = `
        <strong>Debug Info:</strong><br>
        Total blocks: ${blocks.length}<br>
        Visible blocks: ${visibleBlocks.length}<br>
        Current filter: ${currentFilter || 'None'}<br>
        Modules found: ${JSON.stringify(moduleInfo, null, 2)}
    `;
}

function applyCurrentFilter() {
    if (currentFilter) {
        document.querySelectorAll('.block').forEach(b => {
            const blockModule = b.getAttribute('data-module');
            b.style.display = blockModule === currentFilter ? 'block' : 'none';
        });
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('Page loaded, initializing...');
    updateDebugInfo();
    
    // Initialize content count for auto-reload
    const initialBlocks = document.querySelectorAll('.block');
    lastContentCount = initialBlocks.length;
    console.log('Initial block count:', lastContentCount);
});

// Auto-reload functionality
let lastContentCount = 0;
async function checkUpdate() {
    try {
        const res = await fetch("/output/report.html", { cache: "no-store" });
        const text = await res.text();
        const matches = text.match(/<div class="block"/g);
        const currentCount = matches ? matches.length : 0;
        
        if (currentCount !== lastContentCount && lastContentCount > 0) {
            console.log('Content updated, reloading...');
            lastContentCount = currentCount;
            location.reload();
        } else if (lastContentCount === 0) {
            lastContentCount = currentCount;
        }
    } catch (err) {
        console.warn("Live update check failed:", err);
    }
}

setInterval(checkUpdate, 3000); // check every 3 seconds""")

    # Create HTML file
    if not os.path.exists(REPORT_HTML):
        with open(REPORT_HTML, "w", encoding="utf-8") as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SpecterX Recon Report</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <h1>SpecterX Recon Report <span class="live-dot"></span></h1>

  <div class="filters">
    <button onclick="showAll(event)" class="active">Show All</button>
    <button onclick="filter(event, 'Subdomain Scanner')">Subdomain Scanner</button>
    <button onclick="filter(event, 'Port Scanner')">Port Scanner</button>
    <button onclick="filter(event, 'Lan Ip Scanner')">LAN IP Scanner</button>
    <button onclick="filter(event, 'Web Fingerprinter')">Web Fingerprinter</button>
    <button onclick="filter(event, 'Username Osint')">Username OSINT</button>
    <button onclick="filter(event, 'Email Osint')">Email OSINT</button>
    <button onclick="filter(event, 'Exploit Matcher')">Exploit Matcher</button>
    <button onclick="filter(event, 'Brute Force Results')">Brute-Force</button>
  </div>

  <div id="debug-info" class="debug-info">
    Debug info will appear here...
  </div>

  <div id="content-container">
    <!-- New content will be inserted here -->
  </div>

  <script src="script.js"></script>
</body>
</html>""")


def write_html_section(module_name, content_lines):
    init_html_report()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Enhanced name mapping with debug output
    name_mapping = {
        'subdomain scanner': 'Subdomain Scanner',
        'port scanner': 'Port Scanner', 
        'lan ip scanner': 'Lan Ip Scanner',
        'web fingerprinter': 'Web Fingerprinter',
        'username osint': 'Username Osint',
        'email osint': 'Email Osint',
        'exploit matcher': 'Exploit Matcher',
        'brute-force results': 'Brute Force Results',
        'brute-force': 'Brute Force Results',
        'brute force results': 'Brute Force Results'
    }
    
    normalized_name = name_mapping.get(module_name.lower(), module_name.title())
    print(f"[DEBUG] Original module name: '{module_name}' -> Normalized: '{normalized_name}'")
    
    new_block = f"""
<div class="block" data-module="{normalized_name}">
  <h2 class="section-title">{normalized_name}</h2>
  <div class="timestamp">{timestamp}</div>
  <pre>{chr(10).join(content_lines)}</pre>
</div>"""

    # Read existing content and insert at top
    if os.path.exists(REPORT_HTML):
        with open(REPORT_HTML, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Find the content container and insert new block at the top
        container_pos = content.find('<div id="content-container">')
        if container_pos != -1:
            # Find the end of the opening tag
            insert_pos = content.find('>', container_pos) + 1
            # Insert new block right after the opening container tag
            updated_content = content[:insert_pos] + new_block + content[insert_pos:]
            
            with open(REPORT_HTML, "w", encoding="utf-8") as f:
                f.write(updated_content)
            
            print(f"[DEBUG] Added block for '{normalized_name}' to report")
        else:
            print("[DEBUG] Content container not found, appending to end")
            with open(REPORT_HTML, "a", encoding="utf-8") as f:
                f.write(new_block)
    else:
        # File doesn't exist, create it first
        print("[DEBUG] Report file doesn't exist, creating new one")
        init_html_report()
        with open(REPORT_HTML, "a", encoding="utf-8") as f:
            f.write(new_block)