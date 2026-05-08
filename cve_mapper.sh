#!/bin/bash

# --- CONFIGURATION VARIABLES ---
TARGET="infrastructure.txt"
SKILL="vuln-scanner"
PROVIDER="openrouter"
MODEL="moonshotai/kimi-k2.6" # Or claude-3.5-sonnet if available
HOST_OUTPUT_DIR="$PWD/generated_reports"
mkdir -p "$HOST_OUTPUT_DIR"

# NEW: We define the exact path as seen by the agent inside Docker
TARGET_IN_DOCKER="/workspace/$TARGET"

# The prompt now uses the absolute path of the mounted file
PROMPT="Analyze the architecture described in the absolute file $TARGET_IN_DOCKER and generate the final report. You MUST save ALL your files in the absolute directory /output/. Do not save anything anywhere else."
# ----------------------------------

if [ ! -f "$TARGET" ]; then
    echo "Error: The file $TARGET does not exist in the current directory ($PWD)."
    exit 1
fi

echo "Configuring environment..."
# Sandbox execution for file writes
hermes config set terminal.backend docker
hermes config set terminal.docker_mount_cwd_to_workspace true
hermes config set terminal.docker_volumes "[\"$HOST_OUTPUT_DIR:/output\"]"
hermes config set terminal.docker_run_as_host_user true

echo "Launching analysis via native MCP tools..."
# Agent launch
hermes chat --skills "$SKILL" --provider "$PROVIDER" -m "$MODEL" -q "$PROMPT" --yolo --accept-hooks
