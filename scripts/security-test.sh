#!/bin/bash
# Security test runner for v1.18 security hardening validation
# Discovers and runs all security regression tests with comprehensive reporting

set -e

# Default settings
VERBOSE=false
HELP=false
LIST_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -l|--list)
            LIST_ONLY=true
            shift
            ;;
        -h|--help)
            HELP=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            HELP=true
            shift
            ;;
    esac
done

if [ "$HELP" = true ]; then
    echo "Usage: $0 [options]"
    echo ""
    echo "Run all security regression tests for v1.18 security hardening."
    echo ""
    echo "Options:"
    echo "  -v, --verbose    Show verbose test output"
    echo "  -l, --list       List security test files without running"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Test Discovery:"
    echo "  - Finds all *_security_test.go and *security*test*.go files"
    echo "  - Runs tests matching TestSecurityRegression pattern"
    echo "  - Uses -race flag to detect race conditions"
    echo "  - Uses -count=1 to disable test caching"
    echo ""
    echo "Exit Codes:"
    echo "  0  All security tests passed"
    echo "  1  One or more security tests failed"
    echo ""
    exit 0
fi

echo "=============================================="
echo "Security Regression Test Runner (v1.18)"
echo "=============================================="
echo ""

# Find all security test files
SECURITY_TEST_FILES=$(find . -name '*_security_test.go' -o -name '*security*test*.go' 2>/dev/null | grep -v vendor | sort -u)

# Extract unique packages from test files
SECURITY_PACKAGES=$(echo "$SECURITY_TEST_FILES" | xargs -I {} dirname {} | sort -u)

echo "Security Test Files Found:"
echo "--------------------------"
FILE_COUNT=0
for file in $SECURITY_TEST_FILES; do
    echo "  $file"
    FILE_COUNT=$((FILE_COUNT + 1))
done
echo ""
echo "Total: $FILE_COUNT security test files"
echo ""

if [ "$LIST_ONLY" = true ]; then
    echo "Packages containing security tests:"
    echo "------------------------------------"
    for pkg in $SECURITY_PACKAGES; do
        echo "  $pkg"
    done
    exit 0
fi

echo "Packages to Test:"
echo "-----------------"
for pkg in $SECURITY_PACKAGES; do
    echo "  $pkg"
done
echo ""

# Build test command
TEST_FLAGS="-race -count=1"
if [ "$VERBOSE" = true ]; then
    TEST_FLAGS="$TEST_FLAGS -v"
fi

echo "Running: go test $TEST_FLAGS -run TestSecurityRegression ./..."
echo ""
echo "=============================================="
echo "Test Execution"
echo "=============================================="
echo ""

# Run tests and capture output
START_TIME=$(date +%s)

# Create temp file for output
OUTPUT_FILE=$(mktemp)
trap "rm -f $OUTPUT_FILE" EXIT

# Run tests
set +e
go test $TEST_FLAGS -run "TestSecurityRegression" ./... 2>&1 | tee "$OUTPUT_FILE"
TEST_EXIT_CODE=${PIPESTATUS[0]}
set -e

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "=============================================="
echo "Security Test Summary"
echo "=============================================="
echo ""
echo "Duration: ${DURATION}s"
echo ""

# Count results by package
echo "Results by Package:"
echo "-------------------"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

while read -r pkg; do
    # Count tests for this package
    pkg_output=$(grep -E "^(ok|FAIL|---|\?)" "$OUTPUT_FILE" | grep "$pkg" || true)

    if echo "$pkg_output" | grep -q "^ok"; then
        status="PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
    elif echo "$pkg_output" | grep -q "^FAIL"; then
        status="FAIL"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    elif echo "$pkg_output" | grep -q "^\?"; then
        status="SKIP"
        SKIP_COUNT=$((SKIP_COUNT + 1))
    else
        status="????"
    fi

    printf "  %-40s %s\n" "$pkg" "$status"
done <<< "$SECURITY_PACKAGES"

echo ""

# Check for SECURITY VIOLATION markers in output
VIOLATIONS=$(grep -c "SECURITY VIOLATION" "$OUTPUT_FILE" 2>/dev/null || echo "0")
if [ "$VIOLATIONS" != "0" ]; then
    echo "WARNING: $VIOLATIONS SECURITY VIOLATION markers found in test output!"
    echo ""
    echo "Violation Details:"
    grep -B 5 "SECURITY VIOLATION" "$OUTPUT_FILE" || true
    echo ""
fi

# Count total tests
TOTAL_TESTS=$(grep -cE "^--- (PASS|FAIL|SKIP):" "$OUTPUT_FILE" 2>/dev/null || echo "0")
PASSED_TESTS=$(grep -cE "^--- PASS:" "$OUTPUT_FILE" 2>/dev/null || echo "0")
FAILED_TESTS=$(grep -cE "^--- FAIL:" "$OUTPUT_FILE" 2>/dev/null || echo "0")
SKIPPED_TESTS=$(grep -cE "^--- SKIP:" "$OUTPUT_FILE" 2>/dev/null || echo "0")

echo "Test Counts:"
echo "------------"
echo "  Total:   $TOTAL_TESTS"
echo "  Passed:  $PASSED_TESTS"
echo "  Failed:  $FAILED_TESTS"
echo "  Skipped: $SKIPPED_TESTS"
echo ""

echo "Package Summary:"
echo "----------------"
echo "  Packages tested: $((PASS_COUNT + FAIL_COUNT))"
echo "  Packages passed: $PASS_COUNT"
echo "  Packages failed: $FAIL_COUNT"
echo "  Packages skipped: $SKIP_COUNT"
echo ""

if [ "$TEST_EXIT_CODE" -ne 0 ]; then
    echo "=============================================="
    echo "SECURITY TESTS FAILED"
    echo "=============================================="
    echo ""
    echo "Failed packages:"
    grep "^FAIL" "$OUTPUT_FILE" || true
    echo ""
    exit 1
fi

echo "=============================================="
echo "ALL SECURITY TESTS PASSED"
echo "=============================================="
echo ""
exit 0
