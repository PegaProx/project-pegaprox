#!/bin/bash
# ============================================================================
# PegaProx Build Script - Concat & Pre-compile JSX
# ============================================================================
#
# LW: Created 25.01.2026 with help from Claude (AI)
# @gyptazy: Modified 26.01.2026 for path evaluation and minor fixes
# NS: Feb 2026 - Updated for web/src/ split (16 feature files)
#
# What this does:
#   - Concatenates web/src/*.js in dependency order
#   - Combines with HTML shell (index.html.original)
#   - Compiles JSX with Babel (once, not every page load)
#   - Wraps it so it waits for React to load first
#   - Result: 2-3 seconds instead of 15+ seconds!
#
# Requirements: Node.js 16+ (for Babel)
#
# Usage:
#   ./build.sh              # Build the compiled version
#   ./build.sh --restore    # Dev mode (Babel compiles in browser)
#
# After editing web/src/*.js, run this again to rebuild.
# The compiled web/index.html is what gets deployed to users.
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

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

# Source files in dependency order
SRC_FILES=(
    constants.js
    translations.js
    contexts.js
    auth.js
    icons.js
    ui.js
    datacenter.js
    security.js
    storage.js
    tables.js
    vm_modals.js
    vm_config.js
    node_modals.js
    create_modals.js
    settings_modal.js
    dashboard.js
)

# Verify all source files exist
for f in "${SRC_FILES[@]}"; do
    if [ ! -f "web/src/$f" ]; then
        echo -e "${RED}✗ Missing source file: web/src/$f${NC}"
        exit 1
    fi
done
echo -e "${GREEN}✓ All ${#SRC_FILES[@]} source files found${NC}"

# Check for HTML shell
if [ ! -f "web/index.html.original" ]; then
    echo -e "${RED}✗ web/index.html.original not found!${NC}"
    exit 1
fi

# Verify shell has the insert marker
if ! grep -q "PEGAPROX_JSX_INSERT" web/index.html.original; then
    echo -e "${RED}✗ web/index.html.original missing PEGAPROX_JSX_INSERT marker!${NC}"
    echo "  The HTML shell needs the <!-- PEGAPROX_JSX_INSERT --> comment."
    exit 1
fi
echo -e "${GREEN}✓ HTML shell with JSX insert marker${NC}"

# --restore flag: dev mode with in-browser Babel compilation
if [ "$1" == "--restore" ]; then
    echo ""
    echo -e "${YELLOW}Building dev version (Babel compiles in browser)...${NC}"

    # Concatenate source files
    JSX_CONTENT=""
    for f in "${SRC_FILES[@]}"; do
        JSX_CONTENT+="$(cat "web/src/$f")"
        JSX_CONTENT+=$'\n'
    done

    # Build HTML: shell + <script type="text/babel"> + jsx + </script></body></html>
    # Replace everything from the marker line onwards
    python3 -c "
import sys
with open('web/index.html.original', 'r') as f:
    shell = f.read()

# Read concatenated JSX from stdin
jsx = sys.stdin.read()

# Find the marker and replace from there
marker = '    <!-- PEGAPROX_JSX_INSERT -->'
idx = shell.find(marker)
if idx == -1:
    print('ERROR: PEGAPROX_JSX_INSERT marker not found', file=sys.stderr)
    sys.exit(1)

html_before = shell[:idx]
new_html = html_before + '<script type=\"text/babel\">\n' + jsx + '\n    </script>\n\n</body>\n</html>\n'

with open('web/index.html', 'w') as f:
    f.write(new_html)

print(f'  Dev build: {len(new_html):,} bytes')
" <<< "$JSX_CONTENT"

    echo -e "${GREEN}✓ Dev build complete (web/index.html)${NC}"
    echo "  Babel will compile JSX in the browser (slower but good for development)"
    echo "  Run ./build.sh again (without --restore) to create production build"
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
    cd "$PROJECT_ROOT"
    echo -e "${GREEN}✓ Babel installed${NC}"
fi

echo ""
echo -e "${YELLOW}Building production version...${NC}"

# Step 1: Concatenate source files
echo -e "${BLUE}→ Concatenating ${#SRC_FILES[@]} source files...${NC}"

cat /dev/null > "$BUILD_DIR/app.jsx"
for f in "${SRC_FILES[@]}"; do
    cat "web/src/$f" >> "$BUILD_DIR/app.jsx"
    echo "" >> "$BUILD_DIR/app.jsx"
done

JSX_SIZE=$(wc -c < "$BUILD_DIR/app.jsx")
JSX_LINES=$(wc -l < "$BUILD_DIR/app.jsx")
echo "  Concatenated: ${JSX_LINES} lines, ${JSX_SIZE} bytes"

# Step 2: Compile JSX with Babel
echo -e "${BLUE}→ Compiling JSX with Babel...${NC}"

BABEL_CMD="$BUILD_DIR/node_modules/.bin/babel"
# Run from .build/ dir so Babel finds node_modules/@babel/preset-react
(cd "$BUILD_DIR" && "$BABEL_CMD" app.jsx -o app.js --presets=@babel/preset-react)

JS_SIZE=$(wc -c < "$BUILD_DIR/app.js")
echo "  Compiled JS: ${JS_SIZE} bytes"

# Step 3: Build final HTML
echo -e "${BLUE}→ Assembling final HTML...${NC}"

export PEGAPROX_BUILD_DIR="$BUILD_DIR"
export PEGAPROX_PROJECT_ROOT="$PROJECT_ROOT"

python3 << 'PYTHON_SCRIPT'
import os

build_dir = os.environ["PEGAPROX_BUILD_DIR"]
project_root = os.environ["PEGAPROX_PROJECT_ROOT"]
web_dir = os.path.join(project_root, 'web')

# Read HTML shell
with open(os.path.join(web_dir, 'index.html.original'), 'r', encoding='utf-8') as f:
    shell = f.read()

# Read compiled JS
with open(os.path.join(build_dir, 'app.js'), 'r', encoding='utf-8') as f:
    compiled_js = f.read()

# Find insert marker
marker = '    <!-- PEGAPROX_JSX_INSERT -->'
idx = shell.find(marker)
if idx == -1:
    print("ERROR: PEGAPROX_JSX_INSERT marker not found!")
    exit(1)

html_before = shell[:idx]

# Wrap compiled JS in waitForReact IIFE
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

# Build final HTML
new_html = html_before + '<script>\n' + wrapped_js + '\n    </script>\n\n</body>\n</html>\n'

# Disable Babel.transformScriptTags() since JSX is pre-compiled
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
new_comment = "// Load in sequence - JSX pre-compiled, Babel loads but skips\n        // Edit web/src/*.js, then run web/Dev/build.sh"
new_html = new_html.replace(old_comment, new_comment)

# Write output
output_file = os.path.join(web_dir, 'index.html')
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(new_html)

print(f"  Shell:    {len(shell):,} bytes")
print(f"  JS:       {len(compiled_js):,} bytes")
print(f"  Output:   {len(new_html):,} bytes")

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
echo -e "  ${BLUE}Source:${NC}  web/src/ (${#SRC_FILES[@]} files)"
echo -e "  ${BLUE}Output:${NC}  web/index.html (pre-compiled)"
echo ""
echo -e "  For development: ${YELLOW}./build.sh --restore${NC}"
echo -e "  After changes:   ${YELLOW}./build.sh${NC}"
echo ""
