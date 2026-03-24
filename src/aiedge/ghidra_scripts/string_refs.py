# Ghidra headless script for SCOUT
# @category SCOUT
# @description Extract string references with cross-reference context
#
# Invoked by ghidra_bridge.py via:
#   analyzeHeadless ... -postScript string_refs.py <output_json_path>
#
# Note: This script runs with -noanalysis for speed (string extraction only).
#
# Globals provided by Ghidra runtime: currentProgram, monitor, getScriptArgs

import json
import re

# Patterns of interest in firmware strings
INTERESTING_PATTERNS = [
    (r"password|passwd|pwd", "credential"),
    (r"https?://", "url"),
    (r"\d+\.\d+\.\d+\.\d+", "ip_address"),
    (r"/etc/shadow|/etc/passwd", "sensitive_path"),
    (r"BEGIN.*PRIVATE KEY", "private_key"),
    (r"api[_\-]?key|token|secret", "secret"),
    (r"version\s*[:=]\s*\d", "version_string"),
    (r"/dev/mtd|/dev/mem|/proc/", "device_path"),
    (r"system\(|popen\(|exec\(", "command_execution"),
]


def run():
    args = getScriptArgs()  # noqa: F821 — Ghidra global
    output_path = args[0] if args else "/tmp/strings_output.json"

    results = {"strings": [], "categorized": {}, "errors": []}

    try:
        from ghidra.program.util import DefinedDataIterator

        prog = currentProgram  # noqa: F821
        ref_mgr = prog.getReferenceManager()
        fm = prog.getFunctionManager()

        count = 0
        max_strings = 5000

        for data in DefinedDataIterator.definedStrings(prog):
            if count >= max_strings:
                break

            try:
                value = data.getDefaultValueRepresentation()
                if not value or len(value) < 4:
                    continue

                # Clean the string representation (Ghidra wraps in quotes)
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]

                # Find cross-references to this string
                xrefs = []
                for ref in ref_mgr.getReferencesTo(data.getAddress()):
                    caller = fm.getFunctionContaining(ref.getFromAddress())
                    xrefs.append({
                        "from_address": str(ref.getFromAddress()),
                        "from_function": caller.getName() if caller else "unknown",
                    })

                # Categorize by interesting patterns
                categories = []
                for pattern, category in INTERESTING_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        categories.append(category)
                        results["categorized"].setdefault(category, 0)
                        results["categorized"][category] = \
                            results["categorized"][category] + 1

                if categories or xrefs:
                    entry = {
                        "address": str(data.getAddress()),
                        "value": value[:500],
                        "categories": categories,
                        "xref_count": len(xrefs),
                        "xrefs": xrefs[:20],  # Limit xrefs per string
                    }
                    results["strings"].append(entry)
                    count += 1

            except Exception as e:
                results["errors"].append(str(e))

        results["total_strings_analyzed"] = count

    except Exception as e:
        results["fatal_error"] = str(e)

    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)


run()
