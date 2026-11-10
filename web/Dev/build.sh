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
#   - LW Nov 2026: keeps English in the bundle and writes every other language
#     to web/i18n/<lang>.json, with a hash of each in the page (?v= of its URL)
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
    api_errors.js
    translations.js
    contexts.js
    auth.js
    icons.js
    ui.js
    datacenter.js
    security.js
    storage.js
    networking.js
    tables.js
    vm_modals.js
    vm_config.js
    vnc_secure_socket.js
    node_modals.js
    create_modals.js
    settings_modal.js
    worldmap.js
    cloud.js
    cr.js
    cr_views.js
    cr_topology.js
    cr_compliance.js
    cr_tasks.js
    cr_datastore.js
    cr_drift.js
    cr_storage.js
    cr_recovery.js
    cr_sla.js
    cr_isosync.js
    cr_vm.js
    cr_reports.js
    cr_whatif.js
    cr_harden.js
    cr_alerts.js
    cr_datacenter.js
    cr_updates.js
    cr_perf.js
    cr_vmcfg.js
    cr_node.js
    cr_nodecfg.js
    cr_nodestore.js
    cr_nodemisc.js
    cr_modules.js
    cr_blueprints.js
    cr_images.js
    blueprints.js
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

export PEGAPROX_BUILD_DIR="$BUILD_DIR"
export PEGAPROX_PROJECT_ROOT="$PROJECT_ROOT"

# Step 1: Split the translations
# LW Nov 2026 - translations.js was more than half of the bundle, and a browser shows one
# language. English stays in (the fallback of t(), so a language file that does not come
# never leaves the page without text), the others become web/i18n/<lang>.json. The values
# come from the file evaluated as it is, the English block goes in as written.
echo -e "${BLUE}→ Writing the language files...${NC}"

node - << 'NODE_SCRIPT'
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vm = require('vm');

const buildDir = process.env.PEGAPROX_BUILD_DIR;
const root = process.env.PEGAPROX_PROJECT_ROOT;
const srcFile = path.join(root, 'web', 'src', 'translations.js');
const src = fs.readFileSync(srcFile, 'utf8');
const fail = (msg) => { console.error(`ERROR: web/src/translations.js: ${msg}`); process.exit(1); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// the values as the browser gets them: the file evaluated as it is
const all = vm.runInNewContext(src + '\n;translations;', {}, { filename: srcFile });
const langs = Object.keys(all);
const lines = src.split('\n');
const opened = lines.filter(l => /^            [a-z]{2}: \{$/.test(l)).map(l => l.trim().slice(0, 2));
if (!all.en || !same(opened, langs)) fail(`expected one "<lang>: {" block per language, found ${opened}`);

// the English block as written, cut from its line to the one that closes it, and only
// taken when it evaluates to exactly what the whole file gives for English
const first = lines.indexOf('            en: {');
let last = first + 1;
while (last < lines.length && !/^            \}/.test(lines[last])) last++;
const english = lines.slice(first, last).join('\n') + '\n            }';
if (!same(vm.runInNewContext(`({\n${english}\n})`, {}).en, all.en)) fail('the en block could not be cut out as written');

const outDir = path.join(root, 'web', 'i18n');
fs.mkdirSync(outDir, { recursive: true });
const hashes = {};
for (const lang of langs) {
    if (lang === 'en') continue;
    const text = JSON.stringify(all[lang]) + '\n';
    fs.writeFileSync(path.join(outDir, `${lang}.json`), text);
    hashes[lang] = crypto.createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 16);
    console.log(`  ${lang}.json: ${Buffer.byteLength(text).toLocaleString('en')} bytes (${hashes[lang]})`);
}
// a language that left the source leaves web/i18n as well
for (const f of fs.readdirSync(outDir)) {
    if (f.endsWith('.json') && !Object.prototype.hasOwnProperty.call(hashes, f.slice(0, -5))) {
        fs.unlinkSync(path.join(outDir, f));
    }
}
fs.writeFileSync(path.join(buildDir, 'translations.en.js'), `const translations = {\n${english},\n        };\n`);
fs.writeFileSync(path.join(buildDir, 'i18n.json'), JSON.stringify(hashes));
NODE_SCRIPT

# Step 2: Concatenate source files
echo -e "${BLUE}→ Concatenating ${#SRC_FILES[@]} source files...${NC}"

cat /dev/null > "$BUILD_DIR/app.jsx"
for f in "${SRC_FILES[@]}"; do
    if [ "$f" == "translations.js" ]; then
        cat "$BUILD_DIR/translations.en.js" >> "$BUILD_DIR/app.jsx"
    else
        cat "web/src/$f" >> "$BUILD_DIR/app.jsx"
    fi
    echo "" >> "$BUILD_DIR/app.jsx"
done

JSX_SIZE=$(wc -c < "$BUILD_DIR/app.jsx")
JSX_LINES=$(wc -l < "$BUILD_DIR/app.jsx")
echo "  Concatenated: ${JSX_LINES} lines, ${JSX_SIZE} bytes"

# Step 3: Compile JSX with Babel
echo -e "${BLUE}→ Compiling JSX with Babel...${NC}"

BABEL_CMD="$BUILD_DIR/node_modules/.bin/babel"
# Run from .build/ dir so Babel finds node_modules/@babel/preset-react
(cd "$BUILD_DIR" && "$BABEL_CMD" app.jsx -o app.js --presets=@babel/preset-react)

JS_SIZE=$(wc -c < "$BUILD_DIR/app.js")
echo "  Compiled JS: ${JS_SIZE} bytes"

# Step 4: Build final HTML
echo -e "${BLUE}→ Assembling final HTML...${NC}"

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

# LW Nov 2026 - the head asks for the language file the page opens in, by these hashes
with open(os.path.join(build_dir, 'i18n.json'), 'r', encoding='utf-8') as f:
    i18n_files = f.read().strip()
i18n_marker = 'window.__pegaproxI18nFiles = {};'
if html_before.count(i18n_marker) != 1:
    print("ERROR: the language file marker is not in the <head> of index.html.original once!")
    exit(1)
html_before = html_before.replace(i18n_marker, 'window.__pegaproxI18nFiles = ' + i18n_files + ';')

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

# NS Jul 2026 (perf): production JSX is pre-compiled, so @babel/standalone (~3MB /
# ~665KB gz) is downloaded + parsed for nothing AND blocks the 5 libs after it in
# the serial loader chain. Strip the babel loadScriptWithFallback() step from the
# PRODUCTION output only — the --restore dev path keeps it (index.html.original is
# untouched) because it transpiles <script type=text/babel> in the browser.
babel_load_step = '''        }).then(function() {
            return loadScriptWithFallback(
                'https://cdn.jsdelivr.net/npm/@babel/standalone@7.29.2/babel.min.js',
                '/static/js/babel.min.js',
                'babel@7.29.2'
            );
'''
if babel_load_step in new_html:
    new_html = new_html.replace(babel_load_step, '')
    print('  Stripped @babel/standalone loader (prod, pre-compiled JSX)')
else:
    print('  [warn] babel loader step not found to strip (loader chain changed?)')

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
echo -e "           web/i18n/<lang>.json (every language but English)"
echo ""
echo -e "  For development: ${YELLOW}./build.sh --restore${NC}"
echo -e "  After changes:   ${YELLOW}./build.sh${NC}"
echo ""
