#!/bin/sh

set -e

cd "$(dirname "$0")"
mypy --no-error-summary musig.py
python3 musig.py
python3 musig_gen_vectors_helper.py > /dev/null