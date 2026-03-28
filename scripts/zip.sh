#!/bin/bash

ZIP_NAME="ccs.zip"
TARGETS=("src" "tests" "scripts" "README.md" "pyproject.toml" "CLAUDE.md" "LICENSE")

echo "removing __pycache__"
find . -type d -name "__pycache__" -exec rm -r {} +
echo "zipping $ZIP_NAME"
zip -r "$ZIP_NAME" "${TARGETS[@]}"

echo "done"
