#!/bin/bash
# update_nuclei_templates.sh
# Update nuclei templates before scanning to ensure latest CVE checks are available.
# This script should be run before every scan session.

set -euo pipefail

echo "=== Nuclei Template Update ==="

# Check if nuclei is installed
if ! command -v nuclei &> /dev/null; then
    echo "[ERROR] nuclei is not installed or not in PATH"
    echo "Install nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    exit 1
fi

echo "[INFO] nuclei found at: $(which nuclei)"
echo "[INFO] nuclei version: $(nuclei -version 2>&1 | head -1)"

# Update templates
echo "[INFO] Updating nuclei templates..."
if nuclei -update-templates 2>&1; then
    echo "[INFO] Templates updated successfully"
else
    echo "[WARNING] Template update completed with warnings (non-fatal)"
fi

# Report template count
TEMPLATE_DIR="${HOME}/nuclei-templates"
if [ -d "$TEMPLATE_DIR" ]; then
    TEMPLATE_COUNT=$(find "$TEMPLATE_DIR" -name '*.yaml' -o -name '*.yml' 2>/dev/null | wc -l)
    echo "[INFO] Total templates available: $TEMPLATE_COUNT"
else
    # Try common alternate locations
    for dir in /root/nuclei-templates /opt/nuclei-templates ~/.local/nuclei-templates; do
        if [ -d "$dir" ]; then
            TEMPLATE_COUNT=$(find "$dir" -name '*.yaml' -o -name '*.yml' 2>/dev/null | wc -l)
            echo "[INFO] Total templates available ($dir): $TEMPLATE_COUNT"
            break
        fi
    done
fi

# Count CVE-specific templates
CVE_COUNT=$(find "${HOME}/nuclei-templates" -name '*.yaml' -o -name '*.yml' 2>/dev/null | xargs grep -l 'cve' 2>/dev/null | wc -l || echo "0")
echo "[INFO] CVE-specific templates: $CVE_COUNT"

echo "=== Update Complete ==="
