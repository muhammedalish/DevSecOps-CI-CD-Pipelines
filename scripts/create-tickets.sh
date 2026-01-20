#!/usr/bin/env bash

################################################################################
# Jira Ticket Creation Script for Vulnerabilities
# 
# This script creates Jira tickets for detected vulnerabilities from security
# scanning tools (SAST, SCA, Container Scanning, DAST)
#
# Usage:
#   ./create-tickets.sh -n "Vulnerability Name" -s "Critical" -t "2024-01-20" \
#     -d "Semgrep" -v "SQL Injection" -c "CVE-2024-1234" -r "Update library" \
#     -c "Additional comments"
#
#   Or with environment variables:
#   export VULN_NAME="Vulnerability Name"
#   export VULN_SEVERITY="Critical"
#   export VULN_TIME_DETECTED="2024-01-20"
#   ./create-tickets.sh
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
JIRA_URL="${JIRA_URL:-https://jira.example.com}"
JIRA_USERNAME="${JIRA_USERNAME:-admin}"
JIRA_API_TOKEN="${JIRA_API_TOKEN:-}"
JIRA_PROJECT_KEY="${JIRA_PROJECT_KEY:-DVNA}"
JIRA_ISSUE_TYPE="${JIRA_ISSUE_TYPE:-Bug}"

# Vulnerability details (from arguments or environment variables)
VULN_NAME="${VULN_NAME:-}"
VULN_SEVERITY="${VULN_SEVERITY:-}"
VULN_TIME_DETECTED="${VULN_TIME_DETECTED:-}"
DETECTION_TOOL="${DETECTION_TOOL:-}"
VULN_TYPE="${VULN_TYPE:-}"
CVE_ID="${CVE_ID:-}"
REMEDIATION_STEPS="${REMEDIATION_STEPS:-}"
ADDITIONAL_COMMENTS="${ADDITIONAL_COMMENTS:-}"

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
    -u, --jira-url URL                 Jira URL (default: \$JIRA_URL or https://jira.example.com)
    -U, --jira-username USERNAME       Jira username (default: \$JIRA_USERNAME or admin)
    -P, --jira-project PROJECT_KEY     Jira project key (default: \$JIRA_PROJECT_KEY or DVNA)
    -T, --jira-token TOKEN             Jira API token (required, use \$JIRA_API_TOKEN env var)
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
    JIRA_URL                   Jira URL
    JIRA_USERNAME              Jira username
    JIRA_API_TOKEN             Jira API token
    JIRA_PROJECT_KEY           Jira project key

EXAMPLES:
    # Command line arguments
    $0 -n "SQL Injection" -s "Critical" -t "2024-01-20T10:30:00Z" \\
       -d "Semgrep" -v "SQL Injection" -c "CVE-2024-1234" \\
       -r "Update to patched version" -C "Found in user input validation"

    # Environment variables
    export VULN_NAME="SQL Injection"
    export VULN_SEVERITY="Critical"
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
            -u|--jira-url)
                JIRA_URL="$2"
                shift 2
                ;;
            -U|--jira-username)
                JIRA_USERNAME="$2"
                shift 2
                ;;
            -P|--jira-project)
                JIRA_PROJECT_KEY="$2"
                shift 2
                ;;
            -T|--jira-token)
                JIRA_API_TOKEN="$2"
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
    echo "  5) Other"
    read -p "Select Detection Tool (1-5) or enter custom: " tool_choice
    case $tool_choice in
        1) DETECTION_TOOL="Semgrep" ;;
        2) DETECTION_TOOL="SonarQube" ;;
        3) DETECTION_TOOL="Snyk" ;;
        4) DETECTION_TOOL="Trivy" ;;
        5) read -p "Enter tool name: " DETECTION_TOOL ;;
        *) DETECTION_TOOL="$tool_choice" ;;
    esac
    
    read -p "Vulnerability Type (e.g., SQL Injection, XSS, RCE): " VULN_TYPE
    read -p "CVE ID (e.g., CVE-2024-1234) [optional]: " CVE_ID
    read -p "Remediation Steps: " REMEDIATION_STEPS
    read -p "Additional Comments [optional]: " ADDITIONAL_COMMENTS
    
    echo ""
    read -p "Jira URL [${JIRA_URL}]: " jira_url_input
    [[ -n "$jira_url_input" ]] && JIRA_URL="$jira_url_input"
    
    read -p "Jira Username [${JIRA_USERNAME}]: " jira_user_input
    [[ -n "$jira_user_input" ]] && JIRA_USERNAME="$jira_user_input"
    
    read -sp "Jira API Token: " JIRA_API_TOKEN
    echo ""
    
    read -p "Jira Project Key [${JIRA_PROJECT_KEY}]: " jira_project_input
    [[ -n "$jira_project_input" ]] && JIRA_PROJECT_KEY="$jira_project_input"
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
    
    if [[ -z "$JIRA_API_TOKEN" ]]; then
        print_error "Jira API token is required (use -T option or \$JIRA_API_TOKEN env var)"
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
    echo ""
}

# Create Jira ticket
create_jira_ticket() {
    print_info "Creating Jira ticket..."
    
    # Prepare description with all details
    local description="*Vulnerability Details*
    
*Name:* $VULN_NAME
*Severity:* $VULN_SEVERITY
*Time Detected:* $VULN_TIME_DETECTED
*Detection Tool:* $DETECTION_TOOL
*Vulnerability Type:* ${VULN_TYPE:-Not specified}
*CVE ID:* ${CVE_ID:-Not specified}

*Remediation Steps:*
$REMEDIATION_STEPS

*Additional Comments:*
${ADDITIONAL_COMMENTS:-None}"
    
    # Prepare JSON payload
    local json_payload=$(cat <<EOF
{
  "fields": {
    "project": {
      "key": "$JIRA_PROJECT_KEY"
    },
    "issuetype": {
      "name": "$JIRA_ISSUE_TYPE"
    },
    "summary": "[$VULN_SEVERITY] $VULN_NAME detected by $DETECTION_TOOL",
    "description": "$description",
    "customfield_severity": "$VULN_SEVERITY",
    "labels": [
      "security",
      "vulnerability",
      "${DETECTION_TOOL,,}",
      "dvna"
    ]
  }
}
EOF
)
    
    # Create authentication header
    local auth_header=$(echo -n "$JIRA_USERNAME:$JIRA_API_TOKEN" | base64)
    
    # Make API call to create issue
    local response=$(curl -s -X POST \
        -H "Authorization: Basic $auth_header" \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "$JIRA_URL/rest/api/3/issue")
    
    # Check for errors in response
    if echo "$response" | grep -q '"id"'; then
        local ticket_id=$(echo "$response" | grep -o '"key":"[^"]*' | cut -d'"' -f4)
        print_success "Jira ticket created successfully: $ticket_id"
        echo "$JIRA_URL/browse/$ticket_id"
        return 0
    else
        print_error "Failed to create Jira ticket"
        print_error "Response: $response"
        return 1
    fi
}

# Main execution
main() {
    print_info "Jira Vulnerability Ticket Creator"
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
    
    # Confirm before creating
    if [[ "${AUTO_CONFIRM:-}" != "true" ]]; then
        read -p "Create Jira ticket with above information? (y/n): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            print_info "Ticket creation cancelled"
            exit 0
        fi
    fi
    
    # Create the ticket
    if create_jira_ticket; then
        exit 0
    else
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
