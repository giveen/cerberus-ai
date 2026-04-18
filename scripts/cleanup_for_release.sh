#!/bin/bash
# Cleanup script for Cerberus AI public release
# 
# WARNING: This script performs destructive operations:
# - Removes all .env files (except templates)
# - Clears /logs and /archive directories
# - Flushes Redis cache
# - Validates no proprietary strings remain
#
# DO NOT RUN THIS SCRIPT UNLESS EXPLICITLY REQUESTED FOR RELEASE
# This is a safe-mode script - it will only report, not execute destructive operations
# Pass --force to actually execute deletions

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
FORCE_MODE="${1:-}"
DRY_RUN=true

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check if running in force/execute mode
if [[ "$FORCE_MODE" == "--force" ]]; then
    DRY_RUN=false
    log_warning "RUNNING IN EXECUTE MODE - CHANGES WILL BE MADE"
else
    log_info "Running in SAFE MODE (dry run) - no changes will be made"
    log_info "Pass '--force' as argument to actually execute cleanup"
fi

echo ""
log_info "=== Cerberus AI Sanitization & Cleanup ===="
echo ""

# ============================================================================
# 1. Find and remove .env files (except templates)
# ============================================================================
log_info "Step 1: Checking .env files..."

ENV_FILES_TO_REMOVE=()
ENV_TEMPLATES=()

# Find all .env files
while IFS= read -r -d '' env_file; do
    # Skip .env.template* and .env.example files
    if [[ "$env_file" =~ \.template|\.example ]]; then
        ENV_TEMPLATES+=("$env_file")
    else
        ENV_FILES_TO_REMOVE+=("$env_file")
    fi
done < <(find "$REPO_ROOT" -name ".env*" -type f -print0 2>/dev/null)

if [[ ${#ENV_FILES_TO_REMOVE[@]} -gt 0 ]]; then
    log_warning "Found ${#ENV_FILES_TO_REMOVE[@]} .env files to remove:"
    for env_file in "${ENV_FILES_TO_REMOVE[@]}"; do
        echo "  - $env_file"
    done
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Would remove these files (dry run)"
    else
        for env_file in "${ENV_FILES_TO_REMOVE[@]}"; do
            if rm -f "$env_file"; then
                log_success "Removed: $env_file"
            else
                log_error "Failed to remove: $env_file"
            fi
        done
    fi
else
    log_success "No .env files to remove"
fi

if [[ ${#ENV_TEMPLATES[@]} -gt 0 ]]; then
    log_success "Preserving ${#ENV_TEMPLATES[@]} template files"
fi

echo ""

# ============================================================================
# 2. Clear /logs directory
# ============================================================================
log_info "Step 2: Checking /logs directory..."

LOGS_DIR="$REPO_ROOT/logs"
if [[ -d "$LOGS_DIR" ]]; then
    LOG_COUNT=$(find "$LOGS_DIR" -type f | wc -l)
    
    if [[ $LOG_COUNT -gt 0 ]]; then
        log_warning "Found $LOG_COUNT log files in $LOGS_DIR"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "Would delete these files (dry run)"
            find "$LOGS_DIR" -type f | head -10 | sed 's/^/  - /'
            if [[ $LOG_COUNT -gt 10 ]]; then
                echo "  ... and $((LOG_COUNT - 10)) more files"
            fi
        else
            rm -rf "$LOGS_DIR"/*
            log_success "Cleared /logs directory"
        fi
    else
        log_success "No log files to clear"
    fi
else
    log_success "No /logs directory found"
fi

echo ""

# ============================================================================
# 3. Clear /archive directory
# ============================================================================
log_info "Step 3: Checking /archive directory..."

ARCHIVE_DIR="$REPO_ROOT/archive"
if [[ -d "$ARCHIVE_DIR" ]]; then
    ARCHIVE_COUNT=$(find "$ARCHIVE_DIR" -type f | wc -l)
    
    if [[ $ARCHIVE_COUNT -gt 0 ]]; then
        log_warning "Found $ARCHIVE_COUNT archived files in $ARCHIVE_DIR"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "Would delete these files (dry run)"
            find "$ARCHIVE_DIR" -type f | head -10 | sed 's/^/  - /'
            if [[ $ARCHIVE_COUNT -gt 10 ]]; then
                echo "  ... and $((ARCHIVE_COUNT - 10)) more files"
            fi
        else
            rm -rf "$ARCHIVE_DIR"/*
            log_success "Cleared /archive directory"
        fi
    else
        log_success "No archived files to clear"
    fi
else
    log_success "No /archive directory found"
fi

echo ""

# ============================================================================
# 4. Redis cache flush attempt
# ============================================================================
log_info "Step 4: Checking Redis cache..."

REDIS_URL="${REDIS_URL:-redis://localhost:6379}"

# Try to flush Redis if available
if command -v redis-cli &> /dev/null; then
    if redis-cli -u "$REDIS_URL" ping &>/dev/null; then
        log_warning "Redis is accessible at $REDIS_URL"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "Would flush Redis (dry run)"
        else
            if redis-cli -u "$REDIS_URL" FLUSHALL &>/dev/null; then
                log_success "Flushed Redis cache"
            else
                log_error "Failed to flush Redis"
            fi
        fi
    else
        log_warning "Redis is not accessible (may not be running)"
    fi
else
    log_warning "redis-cli not found - skipping Redis flush"
fi

echo ""

# ============================================================================
# 5. Validate no proprietary strings remain in src/
# ============================================================================
log_info "Step 5: Scanning for proprietary/sensitive strings..."

PROPRIETARY_PATTERNS=(
    "api_key"
    "secret_key"
    "password"
    "AWS_ACCESS"
    "OPENAI_API"
    "DEBUG_CREDENTIALS"
    "PRIVATE_KEY"
    "client_secret"
)

FOUND_ISSUES=0

for pattern in "${PROPRIETARY_PATTERNS[@]}"; do
    # Search in src/ but exclude common safe patterns
    if grep -r "$pattern" "$REPO_ROOT/src" 2>/dev/null | \
        grep -v "example" | \
        grep -v "template" | \
        grep -v "documentation" | \
        grep -v "\.example" | \
        grep -i -q "value\|=.*['\"]"; then
        
        log_warning "Found potential sensitive pattern: $pattern"
        ISSUE_COUNT=$(grep -r "$pattern" "$REPO_ROOT/src" 2>/dev/null | wc -l)
        echo "  Occurrences: $ISSUE_COUNT"
        FOUND_ISSUES=$((FOUND_ISSUES + 1))
    fi
done

if [[ $FOUND_ISSUES -eq 0 ]]; then
    log_success "No obvious proprietary strings found"
else
    log_warning "Found $FOUND_ISSUES potential issues - review manually before release"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================
log_info "=== Cleanup Summary ===="

if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    log_warning "This was a DRY RUN - no changes were made"
    echo ""
    log_info "To execute the cleanup:"
    echo "  bash scripts/cleanup_for_release.sh --force"
    echo ""
    log_warning "WARNING: The --force option will:"
    echo "  • Delete all .env files (not templates)"
    echo "  • Clear all log files in /logs"
    echo "  • Clear all archives in /archive"
    echo "  • Flush Redis cache if available"
else
    echo ""
    log_success "Cleanup completed in EXECUTE mode"
    log_warning "Please review the changes and verify the project is ready for release"
fi

echo ""
