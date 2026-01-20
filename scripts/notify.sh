#!/usr/bin/env bash

################################################################################
# Slack Vulnerability Notification Script
#
# This script sends notifications to a Slack channel when vulnerabilities are
# detected from security scanning tools (SAST, SCA, Container Scanning, DAST)
#
# Usage:
#   ./notify.sh -n "Vulnerability Name" -s "Critical" -t "2024-01-20" \
#     -d "Semgrep" -v "SQL Injection" -c "CVE-2024-1234" -r "Update library" \
#     -C "Additional comments"
#
#   Or with environment variables:
#   export VULN_NAME="Vulnerability Name"
#   export VULN_SEVERITY="Critical"
#   export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
#   ./notify.sh
#
################################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SLACK_WEBHOOK_URL="${SLACK_WEBHOOK_URL:-}"
SLACK_CHANNEL="${SLACK_CHANNEL:-#security-alerts}"
SLACK_USERNAME="${SLACK_USERNAME:-DevSecOps Bot}"
SLACK_ICON_EMOJI="${SLACK_ICON_EMOJI:-:shield:}"
REPOSITORY_NAME="${REPOSITORY_NAME:-dvna}"
REPOSITORY_URL="${REPOSITORY_URL:-https://github.com/appsecco/dvna}"

# Vulnerability details (from arguments or environment variables)
VULN_NAME="${VULN_NAME:-}"
VULN_SEVERITY="${VULN_SEVERITY:-}"
VULN_TIME_DETECTED="${VULN_TIME_DETECTED:-}"
DETECTION_TOOL="${DETECTION_TOOL:-}"
VULN_TYPE="${VULN_TYPE:-}"
CVE_ID="${CVE_ID:-}"
REMEDIATION_STEPS="${REMEDIATION_STEPS:-}"
ADDITIONAL_COMMENTS="${ADDITIONAL_COMMENTS:-}"
BUILD_URL="${BUILD_URL:-}"
BRANCH_NAME="${BRANCH_NAME:-}"

################################################################################
# Functions
################################################################################

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Display usage information
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -n, --name NAME                    Vulnerability name (required)
    -s, --severity LEVEL               Severity level: Critical, High, Medium, Low (required)
    -t, --time-detected DATETIME       Time detected (e.g., 2024-01-20T10:30:00Z) (required)
    -d, --detection-tool TOOL          Detection tool (e.g., Semgrep, Snyk, Trivy) (required)
    -v, --vulnerability-type TYPE      Type of vulnerability (e.g., SQL Injection, XSS)
    -c, --cve CVE_ID                   CVE ID (e.g., CVE-2024-1234)
    -r, --remediation STEPS            Remediation steps (required)
    -C, --comments COMMENTS            Additional comments
    -w, --webhook-url URL              Slack webhook URL (required)
    -ch, --channel CHANNEL             Slack channel (default: #security-alerts)
    -u, --username USERNAME            Slack bot username (default: DevSecOps Bot)
    -R, --repository REPO              Repository name (default: dvna)
    -b, --build-url URL                Build/Pipeline URL
    -B, --branch BRANCH                Git branch name
    -h, --help                         Display this help message
    -i, --interactive                  Interactive mode (prompt for all fields)

ENVIRONMENT VARIABLES:
    VULN_NAME                  Vulnerability name
    VULN_SEVERITY              Severity level
    VULN_TIME_DETECTED         Time detected
    DETECTION_TOOL             Detection tool
    VULN_TYPE                  Vulnerability type
    CVE_ID                     CVE ID
    REMEDIATION_STEPS          Remediation steps
    ADDITIONAL_COMMENTS        Additional comments
    SLACK_WEBHOOK_URL          Slack webhook URL
    SLACK_CHANNEL              Slack channel
    SLACK_USERNAME             Slack bot username
    SLACK_ICON_EMOJI           Slack icon emoji
    REPOSITORY_NAME            Repository name
    REPOSITORY_URL             Repository URL
    BUILD_URL                  Build/Pipeline URL
    BRANCH_NAME                Git branch name

EXAMPLES:
    # Command line arguments
    $0 -n "SQL Injection" -s "Critical" -t "2024-01-20T10:30:00Z" \\
       -d "Semgrep" -v "SQL Injection" -c "CVE-2024-1234" \\
       -r "Update to patched version" -C "Found in user input" \\
       -w "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

    # Environment variables
    export VULN_NAME="SQL Injection"
    export VULN_SEVERITY="Critical"
    export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    $0

    # Interactive mode
    $0 -i

EOF
    exit 1
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -n|--name)
                VULN_NAME="$2"
                shift 2
                ;;
            -s|--severity)
                VULN_SEVERITY="$2"
                shift 2
                ;;
            -t|--time-detected)
                VULN_TIME_DETECTED="$2"
                shift 2
                ;;
            -d|--detection-tool)
                DETECTION_TOOL="$2"
                shift 2
                ;;
            -v|--vulnerability-type)
                VULN_TYPE="$2"
                shift 2
                ;;
            -c|--cve)
                CVE_ID="$2"
                shift 2
                ;;
            -r|--remediation)
                REMEDIATION_STEPS="$2"
                shift 2
                ;;
            -C|--comments)
                ADDITIONAL_COMMENTS="$2"
                shift 2
                ;;
            -w|--webhook-url)
                SLACK_WEBHOOK_URL="$2"
                shift 2
                ;;
            -ch|--channel)
                SLACK_CHANNEL="$2"
                shift 2
                ;;
            -u|--username)
                SLACK_USERNAME="$2"
                shift 2
                ;;
            -R|--repository)
                REPOSITORY_NAME="$2"
                shift 2
                ;;
            -b|--build-url)
                BUILD_URL="$2"
                shift 2
                ;;
            -B|--branch)
                BRANCH_NAME="$2"
                shift 2
                ;;
            -i|--interactive)
                INTERACTIVE_MODE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done
}

# Interactive mode - prompt for all fields
interactive_mode() {
    print_info "Starting interactive mode..."
    echo ""
    
    read -p "Vulnerability Name: " VULN_NAME
    
    echo "Severity Levels:"
    echo "  1) Critical"
    echo "  2) High"
    echo "  3) Medium"
    echo "  4) Low"
    read -p "Select Severity (1-4): " severity_choice
    case $severity_choice in
        1) VULN_SEVERITY="Critical" ;;
        2) VULN_SEVERITY="High" ;;
        3) VULN_SEVERITY="Medium" ;;
        4) VULN_SEVERITY="Low" ;;
        *) VULN_SEVERITY="High" ;;
    esac
    
    read -p "Time Detected (YYYY-MM-DDTHH:MM:SSZ) [default: now]: " VULN_TIME_DETECTED
    [[ -z "$VULN_TIME_DETECTED" ]] && VULN_TIME_DETECTED=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    
    echo "Detection Tools:"
    echo "  1) Semgrep"
    echo "  2) SonarQube"
    echo "  3) Snyk"
    echo "  4) Trivy"
    echo "  5) Grype"
    echo "  6) Other"
    read -p "Select Detection Tool (1-6) or enter custom: " tool_choice
    case $tool_choice in
        1) DETECTION_TOOL="Semgrep" ;;
        2) DETECTION_TOOL="SonarQube" ;;
        3) DETECTION_TOOL="Snyk" ;;
        4) DETECTION_TOOL="Trivy" ;;
        5) DETECTION_TOOL="Grype" ;;
        6) read -p "Enter tool name: " DETECTION_TOOL ;;
        *) DETECTION_TOOL="$tool_choice" ;;
    esac
    
    read -p "Vulnerability Type (e.g., SQL Injection, XSS, RCE): " VULN_TYPE
    read -p "CVE ID (e.g., CVE-2024-1234) [optional]: " CVE_ID
    read -p "Remediation Steps: " REMEDIATION_STEPS
    read -p "Additional Comments [optional]: " ADDITIONAL_COMMENTS
    read -p "Repository Name [${REPOSITORY_NAME}]: " repo_input
    [[ -n "$repo_input" ]] && REPOSITORY_NAME="$repo_input"
    
    read -p "Git Branch [optional]: " BRANCH_NAME
    read -p "Build/Pipeline URL [optional]: " BUILD_URL
    
    echo ""
    read -p "Slack Webhook URL: " SLACK_WEBHOOK_URL
    read -p "Slack Channel [${SLACK_CHANNEL}]: " channel_input
    [[ -n "$channel_input" ]] && SLACK_CHANNEL="$channel_input"
    
    read -p "Slack Username [${SLACK_USERNAME}]: " username_input
    [[ -n "$username_input" ]] && SLACK_USERNAME="$username_input"
}

# Validate required fields
validate_inputs() {
    local errors=0
    
    if [[ -z "$VULN_NAME" ]]; then
        print_error "Vulnerability name is required"
        errors=$((errors + 1))
    fi
    
    if [[ -z "$VULN_SEVERITY" ]]; then
        print_error "Severity level is required"
        errors=$((errors + 1))
    fi
    
    if [[ ! "$VULN_SEVERITY" =~ ^(Critical|High|Medium|Low)$ ]]; then
        print_error "Severity must be one of: Critical, High, Medium, Low"
        errors=$((errors + 1))
    fi
    
    if [[ -z "$VULN_TIME_DETECTED" ]]; then
        VULN_TIME_DETECTED=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
        print_warning "Time detected not provided, using current time: $VULN_TIME_DETECTED"
    fi
    
    if [[ -z "$DETECTION_TOOL" ]]; then
        print_error "Detection tool is required"
        errors=$((errors + 1))
    fi
    
    if [[ -z "$REMEDIATION_STEPS" ]]; then
        print_error "Remediation steps are required"
        errors=$((errors + 1))
    fi
    
    if [[ -z "$SLACK_WEBHOOK_URL" ]]; then
        print_error "Slack webhook URL is required (use -w option or \$SLACK_WEBHOOK_URL env var)"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -gt 0 ]]; then
        print_error "$errors validation error(s) found"
        return 1
    fi
    
    return 0
}

# Display collected information
display_summary() {
    echo ""
    print_info "Vulnerability Summary:"
    echo "  Name: $VULN_NAME"
    echo "  Severity: $VULN_SEVERITY"
    echo "  Time Detected: $VULN_TIME_DETECTED"
    echo "  Detection Tool: $DETECTION_TOOL"
    echo "  Type: ${VULN_TYPE:-Not specified}"
    echo "  CVE ID: ${CVE_ID:-Not specified}"
    echo "  Remediation: $REMEDIATION_STEPS"
    echo "  Comments: ${ADDITIONAL_COMMENTS:-None}"
    echo "  Repository: $REPOSITORY_NAME"
    [[ -n "$BRANCH_NAME" ]] && echo "  Branch: $BRANCH_NAME"
    [[ -n "$BUILD_URL" ]] && echo "  Build URL: $BUILD_URL"
    echo ""
}

# Determine color based on severity
get_severity_color() {
    case "$1" in
        Critical)
            echo "#FF0000"  # Red
            ;;
        High)
            echo "#FF6600"  # Orange
            ;;
        Medium)
            echo "#FFCC00"  # Yellow
            ;;
        Low)
            echo "#0099FF"  # Blue
            ;;
        *)
            echo "#808080"  # Gray
            ;;
    esac
}

# Send Slack notification
send_slack_notification() {
    print_info "Sending Slack notification..."
    
    local severity_color=$(get_severity_color "$VULN_SEVERITY")
    
    # Build fields array
    local fields="["
    
    fields+="{\"title\":\"Vulnerability Name\",\"value\":\"$VULN_NAME\",\"short\":false},"
    fields+="{\"title\":\"Severity\",\"value\":\"$VULN_SEVERITY\",\"short\":true},"
    fields+="{\"title\":\"Detection Tool\",\"value\":\"$DETECTION_TOOL\",\"short\":true},"
    fields+="{\"title\":\"Time Detected\",\"value\":\"$VULN_TIME_DETECTED\",\"short\":true},"
    
    if [[ -n "$VULN_TYPE" ]]; then
        fields+="{\"title\":\"Vulnerability Type\",\"value\":\"$VULN_TYPE\",\"short\":true},"
    fi
    
    if [[ -n "$CVE_ID" ]]; then
        fields+="{\"title\":\"CVE ID\",\"value\":\"<https://nvd.nist.gov/vuln/detail/$CVE_ID|$CVE_ID>\",\"short\":true},"
    fi
    
    fields+="{\"title\":\"Repository\",\"value\":\"<$REPOSITORY_URL|$REPOSITORY_NAME>\",\"short\":true},"
    
    if [[ -n "$BRANCH_NAME" ]]; then
        fields+="{\"title\":\"Branch\",\"value\":\"$BRANCH_NAME\",\"short\":true},"
    fi
    
    fields+="{\"title\":\"Remediation Steps\",\"value\":\"$REMEDIATION_STEPS\",\"short\":false},"
    
    if [[ -n "$ADDITIONAL_COMMENTS" ]]; then
        fields+="{\"title\":\"Additional Comments\",\"value\":\"$ADDITIONAL_COMMENTS\",\"short\":false},"
    fi
    
    # Remove trailing comma
    fields="${fields%,}"
    fields+="]"
    
    # Build attachments
    local attachments="[{"
    attachments+="\"fallback\":\"Vulnerability Alert: $VULN_NAME\","
    attachments+="\"color\":\"$severity_color\","
    attachments+="\"title\":\":alert: SECURITY ALERT: $VULN_SEVERITY Severity Vulnerability Detected\","
    attachments+="\"text\":\"A $VULN_SEVERITY severity vulnerability has been detected in $REPOSITORY_NAME\","
    attachments+="\"fields\":$fields,"
    attachments+="\"ts\":$(date +%s)"
    
    if [[ -n "$BUILD_URL" ]]; then
        attachments+=",\"footer\":\"<$BUILD_URL|View Build Details>\""
    fi
    
    attachments+="}]"
    
    # Build complete JSON payload
    local json_payload="{
        \"channel\":\"$SLACK_CHANNEL\",
        \"username\":\"$SLACK_USERNAME\",
        \"icon_emoji\":\"$SLACK_ICON_EMOJI\",
        \"text\":\"Security Vulnerability Detected\",
        \"attachments\":$attachments
    }"
    
    # Send to Slack
    local response=$(curl -s -X POST \
        -H 'Content-type: application/json' \
        --data "$json_payload" \
        "$SLACK_WEBHOOK_URL")
    
    # Check for success
    if [[ "$response" == "ok" ]]; then
        print_success "Slack notification sent successfully to $SLACK_CHANNEL"
        return 0
    else
        print_error "Failed to send Slack notification"
        print_error "Response: $response"
        return 1
    fi
}

# Main execution
main() {
    print_info "Slack Vulnerability Notifier"
    echo ""
    
    # Check for interactive flag first
    if [[ "${1:-}" == "-i" ]] || [[ "${1:-}" == "--interactive" ]]; then
        INTERACTIVE_MODE=true
        interactive_mode
    else
        # Parse command line arguments
        parse_arguments "$@"
        
        # Check if we need to prompt for inputs
        if [[ -n "${INTERACTIVE_MODE:-}" ]]; then
            interactive_mode
        fi
    fi
    
    # Validate inputs
    if ! validate_inputs; then
        print_error "Validation failed. Use -h for help."
        exit 1
    fi
    
    # Display summary
    display_summary
    
    # Confirm before sending
    if [[ "${AUTO_CONFIRM:-}" != "true" ]]; then
        read -p "Send Slack notification? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            print_info "Notification cancelled"
            exit 0
        fi
    fi
    
    # Send the notification
    if send_slack_notification; then
        exit 0
    else
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
