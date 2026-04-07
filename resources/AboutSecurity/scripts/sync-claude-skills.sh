#!/usr/bin/env bash
# sync-claude-skills.sh
#
# Generates .claude/skills/ symlinks from the nested Skills/ directory.
# This makes AboutSecurity skills compatible with Claude Code,
# which only recognizes .claude/skills/<name>/SKILL.md (flat, one level).
#
# Kitsune uses filepath.WalkDir (recursive) so the nested structure still works.
# Run this script after adding/removing skills.
#
# Usage: ./scripts/sync-claude-skills.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILLS_SRC="$REPO_ROOT/skills"
CLAUDE_DIR="$REPO_ROOT/.claude/skills"

if [ ! -d "$SKILLS_SRC" ]; then
    echo "❌ Skills directory not found: $SKILLS_SRC"
    exit 1
fi

# Create .claude/skills/ if it doesn't exist
mkdir -p "$CLAUDE_DIR"

# Remove existing symlinks (stale cleanup)
find "$CLAUDE_DIR" -maxdepth 1 -type l -delete

# Create symlinks: .claude/skills/<skill-id> → ../../skills/<category>/<skill-id>
count=0
find "$SKILLS_SRC" -name "SKILL.md" -type f | while read -r skill_md; do
    skill_dir="$(dirname "$skill_md")"
    skill_id="$(basename "$skill_dir")"
    rel_path="$(python3 -c "import os.path; print(os.path.relpath('$skill_dir', '$CLAUDE_DIR'))")"
    
    if [ -e "$CLAUDE_DIR/$skill_id" ] && [ ! -L "$CLAUDE_DIR/$skill_id" ]; then
        echo "⚠️  Skipping $skill_id (non-symlink file/dir already exists)"
        continue
    fi
    
    ln -sfn "$rel_path" "$CLAUDE_DIR/$skill_id"
    count=$((count + 1))
done

# Count results
total=$(find "$CLAUDE_DIR" -maxdepth 1 -type l | wc -l | tr -d ' ')
echo "✅ Synced $total skills → .claude/skills/"
echo "   Source: skills/ (nested)"
echo "   Target: .claude/skills/ (flat symlinks)"
