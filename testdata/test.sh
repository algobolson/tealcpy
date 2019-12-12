#!/usr/bin/bash
set -e
set -o pipefail
set -x

for i in *.teal; do
    if [ -f "${i}c" ]; then
	python3 ../tealc.py < "${i}" | diff "${i}c" -
    fi
done
