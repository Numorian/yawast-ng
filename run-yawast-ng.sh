#!/bin/bash
# Wrapper to run yawast-ng in its own pipenv environment from any directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
pipenv run ./bin/yawast-ng "$@"
