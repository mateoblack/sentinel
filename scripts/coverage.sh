#!/bin/bash
# Coverage enforcement script for Sentinel packages
# Enforces 80% minimum coverage threshold on core Sentinel packages

set -e

THRESHOLD=80

# Sentinel packages to check (core functionality)
SENTINEL_PACKAGES=(
    "audit"
    "bootstrap"
    "breakglass"
    "enforce"
    "identity"
    "logging"
    "notification"
    "policy"
    "request"
    "sentinel"
)

# Packages to exclude (base aws-vault code, utilities, thin wrappers)
# - vault: base aws-vault code (already at 31%)
# - iso8601: utility package
# - cli: thin command wrappers
# - prompt: interactive prompts
# - server: http server utilities
# - testutil: test utilities

echo "Coverage Report"
echo "==============="
echo ""

# Run go test with coverage and capture output
COVERAGE_OUTPUT=$(go test -cover ./... 2>&1)

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0
FAILURES=()

for pkg in "${SENTINEL_PACKAGES[@]}"; do
    # Extract coverage percentage for this package
    # Match lines like: ok  github.com/byteness/aws-vault/v7/audit  0.849s  coverage: 91.2% of statements
    coverage_line=$(echo "$COVERAGE_OUTPUT" | grep -E "github.com/byteness/aws-vault/v7/${pkg}\s" | head -1)

    if [ -z "$coverage_line" ]; then
        echo "? ${pkg}: no coverage data found"
        continue
    fi

    # Extract coverage percentage
    coverage=$(echo "$coverage_line" | grep -oE 'coverage: [0-9.]+%' | grep -oE '[0-9.]+')

    if [ -z "$coverage" ]; then
        echo "? ${pkg}: could not parse coverage"
        continue
    fi

    TOTAL_COUNT=$((TOTAL_COUNT + 1))

    # Compare against threshold (using bc for floating point comparison)
    if (( $(echo "$coverage >= $THRESHOLD" | bc -l) )); then
        echo "  ${pkg}: ${coverage}% (threshold: ${THRESHOLD}%)"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "  ${pkg}: ${coverage}% (threshold: ${THRESHOLD}%) BELOW THRESHOLD"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILURES+=("${pkg}: ${coverage}%")
    fi
done

echo ""
echo "Summary: ${PASS_COUNT}/${TOTAL_COUNT} packages meet coverage threshold"

if [ ${FAIL_COUNT} -gt 0 ]; then
    echo ""
    echo "Packages below ${THRESHOLD}% threshold:"
    for failure in "${FAILURES[@]}"; do
        echo "  - ${failure}"
    done
    exit 1
fi

exit 0
