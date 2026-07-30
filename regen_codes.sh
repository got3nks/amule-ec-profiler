#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Regenerate ec_codes.py from the EC code header.
#
# ECCodes.h is the hand-maintained master for the committed enum + name strings
# (ECCodes.java is stale and must be ignored). Re-run this after adding an EC
# opcode or tag so the profiler names it instead of printing OP_0x??.
#
# Usage: ./regen_codes.sh [path/to/amule-src]

set -e
here=$(cd "$(dirname "$0")" && pwd)
src=${1:-$here/../../amule-src}
header=$src/src/libs/ec/cpp/ECCodes.h

if [ ! -f "$header" ]; then
	echo "ECCodes.h not found at: $header" >&2
	echo "pass the amule source root as the first argument" >&2
	exit 1
fi

python3 - "$header" "$here/ec_codes.py" <<'PY'
import re, sys
src, out = sys.argv[1], sys.argv[2]
text = open(src, encoding='utf-8', errors='replace').read()

def enum_body(name):
    m = re.search(r'enum\s+' + name + r'\s*\{(.*?)\};', text, re.S)
    return m.group(1) if m else ''

def parse(name, prefix):
    d = {}
    for em, val in re.findall(r'(' + prefix + r'[A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)', enum_body(name)):
        d.setdefault(int(val, 16) if val.lower().startswith('0x') else int(val), em)
    return d

ops = parse('ECOpCodes', 'EC_OP_')
tags = parse('ECTagNames', 'EC_TAG_')
if not tags:
    tags = {}
    for em, val in re.findall(r'(EC_TAG_[A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)', text):
        tags.setdefault(int(val, 16) if val.lower().startswith('0x') else int(val), em)

with open(out, 'w') as f:
    f.write('# Generated from src/libs/ec/cpp/ECCodes.h -- do not hand-edit.\n')
    f.write('# Regenerate with tools/ec-profiler/regen_codes.sh after an EC code change.\n')
    f.write('# ECCodes.h is the hand-maintained master (ECCodes.java is stale).\n\n')
    for nm, d in (('OPCODES', ops), ('TAGS', tags)):
        f.write(nm + ' = {\n')
        for k in sorted(d):
            f.write('    0x%04X: %r,\n' % (k, d[k]))
        f.write('}\n\n')

print('ec_codes.py: %d opcodes, %d tags' % (len(ops), len(tags)))
PY
