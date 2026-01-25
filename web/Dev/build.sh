#!/bin/bash
# ============================================================================
# PegaProx Build Script - Pre-compile JSX for faster loading
# ============================================================================
# 
# LW: Created 25.01.2026 with help from Claude (AI)
# Was tired of waiting 15 seconds for Babel to compile every page load also issues lol
#
# What this does:
#   - Extracts the JSX from index.html
#   - Compiles it with Babel (once, not every page load)
#   - Wraps it so it waits for React to load first
#   - Result: 2-3 seconds instead of 15+ seconds!
#
# Requirements: Node.js 16+ (for Babel)
#
# Usage:
#   ./build.sh              # Build the compiled version
#   ./build.sh --restore    # Go back to original (for development)
#
# After editing index.html.original, run this again to rebuild.
# The compiled index.html is what gets deployed to users.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          PegaProx Build Script - JSX Pre-Compiler          ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# --restore flag: go back to original for development
if [ "$1" == "--restore" ]; then
    if [ -f "web/index.html.original" ]; then
        cp web/index.html.original web/index.html
        echo -e "${GREEN}✓ Restored original index.html${NC}"
        echo "  You can now edit web/index.html directly"
        echo "  Run ./build.sh again when done to compile"
    else
        echo -e "${RED}✗ No backup found (web/index.html.original)${NC}"
        echo "  Looks like you haven't run a build yet?"
        exit 1
    fi
    exit 0
fi

# Check Node.js - we need it for Babel
if ! command -v node &> /dev/null; then
    echo -e "${RED}✗ Node.js not found!${NC}"
    echo ""
    echo "We need Node.js to run Babel. Install it:"
    echo "  Ubuntu/Debian: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs"
    echo "  Or visit: https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo -e "${RED}✗ Node.js 16+ required (you have v$NODE_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Node.js $(node -v)${NC}"

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}✗ npm not found! Should come with Node.js...${NC}"
    exit 1
fi
echo -e "${GREEN}✓ npm $(npm -v)${NC}"

# Create build directory (hidden, gets gitignored)
BUILD_DIR="$SCRIPT_DIR/.build"
mkdir -p "$BUILD_DIR"

# Install Babel if this is the first run
if [ ! -d "$BUILD_DIR/node_modules/@babel/core" ]; then
    echo ""
    echo -e "${YELLOW}First run - installing Babel (one-time setup)...${NC}"
    cd "$BUILD_DIR"
    
    cat > package.json << 'EOF'
{
  "name": "pegaprox-build",
  "private": true,
  "devDependencies": {
    "@babel/core": "^7.23.0",
    "@babel/cli": "^7.23.0",
    "@babel/preset-react": "^7.23.0"
  }
}
EOF
    
    npm install --silent
    cd "$SCRIPT_DIR"
    echo -e "${GREEN}✓ Babel installed${NC}"
fi

# Check for source file
if [ ! -f "web/index.html" ]; then
    echo -e "${RED}✗ web/index.html not found!${NC}"
    echo "  Are you in the right directory?"
    exit 1
fi

echo ""
echo -e "${YELLOW}Building...${NC}"

# Backup original if this is the first build
if [ ! -f "web/index.html.original" ]; then
    cp web/index.html web/index.html.original
    echo -e "${GREEN}✓ Backed up original to web/index.html.original${NC}"
fi

echo -e "${BLUE}→ Extracting and compiling JSX...${NC}"

# Python does the heavy lifting - Claude wrote most of this part
# Tried doing it in pure bash but the escaping was a nightmare
python3 << 'PYTHON_SCRIPT'
import os
import subprocess
import sys

script_dir = os.getcwd()
build_dir = os.path.join(script_dir, '.build')
web_dir = os.path.join(script_dir, 'web')

# Read the original index.html
with open(os.path.join(web_dir, 'index.html.original'), 'r', encoding='utf-8') as f:
    html_content = f.read()

# Find the <script type="text/babel"> block
# This is where all our React code lives
start_tag = '<script type="text/babel">'
babel_start = html_content.find(start_tag)
if babel_start == -1:
    start_tag = "<script type='text/babel'>"
    babel_start = html_content.find(start_tag)

if babel_start == -1:
    print("ERROR: Could not find <script type=\"text/babel\"> block!")
    print("       Is this the right index.html?")
    sys.exit(1)

content_start = babel_start + len(start_tag)

# Find the closing </script> tag (it's the last one before </body>)
end_patterns = ['</script>\n</body>', '</script>\r\n</body>', '</script></body>']
content_end = -1
for pattern in end_patterns:
    pos = html_content.rfind(pattern)
    if pos > content_start:
        content_end = pos
        break

if content_end == -1:
    content_end = html_content.rfind('</script>')

if content_end <= content_start:
    print("ERROR: Could not find closing </script> tag!")
    sys.exit(1)

jsx_code = html_content[content_start:content_end]
print(f"  Found JSX: {len(jsx_code):,} characters")

# Write JSX to temp file for Babel
jsx_file = os.path.join(build_dir, 'app.jsx')
with open(jsx_file, 'w', encoding='utf-8') as f:
    f.write(jsx_code)

# Run Babel to compile JSX -> JS
print("  Compiling with Babel...")
babel_cmd = os.path.join(build_dir, 'node_modules', '.bin', 'babel')
js_file = os.path.join(build_dir, 'app.js')

result = subprocess.run(
    [babel_cmd, jsx_file, '-o', js_file, '--presets=@babel/preset-react'],
    capture_output=True,
    text=True,
    cwd=build_dir
)

if result.returncode != 0:
    print(f"ERROR: Babel compilation failed!")
    print(result.stderr)
    sys.exit(1)

# Read the compiled JS
with open(js_file, 'r', encoding='utf-8') as f:
    compiled_js = f.read()

print(f"  Compiled JS: {len(compiled_js):,} characters")

# Build the new HTML
# Important: wrap the code so it waits for React to load first
# React loads async, so without this you get "React is not defined" errors
# Took a while to figure this one out...
html_before = html_content[:babel_start]
html_after = html_content[content_end + len('</script>'):]

wrapper_start = '''(function waitForReact() {
    if (typeof React === 'undefined' || typeof ReactDOM === 'undefined') {
        setTimeout(waitForReact, 10);
        return;
    }
    // React is ready, run the app
'''
wrapper_end = '''
})();'''

wrapped_js = wrapper_start + compiled_js + wrapper_end
new_html = html_before + '<script>\n' + wrapped_js + '\n</script>' + html_after

# Disable the Babel.transformScriptTags() call
# Babel still loads but won't do anything (removing it breaks the promise chain)
babel_transform_variations = [
    "if (window.Babel) {\n                Babel.transformScriptTags();\n            }",
    "if (window.Babel) {\r\n                Babel.transformScriptTags();\r\n            }",
    "if (window.Babel) { Babel.transformScriptTags(); }",
]
for variation in babel_transform_variations:
    if variation in new_html:
        new_html = new_html.replace(variation, "// Babel loaded but skipped - JSX pre-compiled by build.sh")
        print("  Disabled Babel.transformScriptTags()")
        break

# Update the loading comment
old_comment = "// Load in sequence - using jsdelivr instead of unpkg (faster + better caching)"
new_comment = "// Load in sequence - JSX pre-compiled, Babel loads but skips\n        // Edit web/index.html.original, then run ./build.sh"
new_html = new_html.replace(old_comment, new_comment)

# Write the final compiled HTML
output_file = os.path.join(web_dir, 'index.html')
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(new_html)

# Show what we did
print(f"\n  Original HTML:  {len(html_content):,} bytes")
print(f"  Compiled HTML:  {len(new_html):,} bytes")

PYTHON_SCRIPT

if [ $? -ne 0 ]; then
    echo -e "${RED}✗ Build failed!${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Build Complete! ✓                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BLUE}Before:${NC} ~15 seconds (Babel compiles in browser every time)"
echo -e "  ${GREEN}After:${NC}  ~2-3 seconds (pre-compiled, just runs)"
echo ""
echo -e "  For development: ${YELLOW}./build.sh --restore${NC}"
echo -e "  After changes:   ${YELLOW}./build.sh${NC}"
echo ""