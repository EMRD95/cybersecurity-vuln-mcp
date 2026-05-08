#!/bin/bash

# --- VARIABLES DE CONFIGURATION ---
TARGET="infrastructure.txt"
SKILL="vuln-scanner"
PROVIDER="openrouter"
MODEL="moonshotai/kimi-k2.6" # Ou claude-3.5-sonnet si disponible
HOST_OUTPUT_DIR="$PWD/generated_reports"
mkdir -p "$HOST_OUTPUT_DIR"

# NOUVEAU : On définit le chemin exact tel qu'il sera vu par l'agent dans Docker
TARGET_IN_DOCKER="/workspace/$TARGET"

# Le prompt utilise maintenant le chemin absolu du fichier monté
PROMPT="Analyse l'architecture décrite dans le fichier absolu $TARGET_IN_DOCKER et génère le rapport final. Sauvegarde IMPÉRATIVEMENT tous tes fichiers dans le dossier absolu /output/. Ne sauvegarde absolument rien ailleurs."
# ----------------------------------

if [ ! -f "$TARGET" ]; then
    echo "❌ Erreur : Le fichier $TARGET n'existe pas dans le dossier courant ($PWD)."
    exit 1
fi

echo "⚙️ Configuration de l'environnement..."
# Exécution du bac à sable pour l'écriture de fichiers
hermes config set terminal.backend docker
hermes config set terminal.docker_mount_cwd_to_workspace true
hermes config set terminal.docker_volumes "[\"$HOST_OUTPUT_DIR:/output\"]"
hermes config set terminal.docker_run_as_host_user true

echo "🔍 Lancement de l'analyse via les outils MCP..."
# Lancement de l'agent
hermes chat --skills "$SKILL" --provider "$PROVIDER" -m "$MODEL" -q "$PROMPT" --yolo --accept-hooks