# DevSecOps-CI-CD-Pipelines

A comprehensive repository containing security-hardened CI/CD pipeline configurations for all major CI/CD platforms. This repository demonstrates best practices for integrating security scanning, policy enforcement, and vulnerability management throughout the software development lifecycle.

## 🎯 Overview

This repository provides production-ready CI/CD pipeline implementations featuring:

- **Automated Security Scanning**: SAST, SCA, DAST, and Secret scanning integrated into every pipeline
- **Infrastructure as Code (IaC) Scanning**: Terraform and CloudFormation vulnerability detection
- **Container Security**: Image scanning and signing with cryptographic verification
- **Policy Enforcement**: Automated pipeline failure on critical vulnerabilities
- **Issue Tracking**: Automatic ticket creation for high and medium severity findings
- **Notifications**: Real-time alerts via Slack, email, and webhooks
- **Compliance Ready**: Support for SOC 2, PCI-DSS, HIPAA, and CIS controls

## 📋 Supported CI/CD Platforms

### Configuration Management
- **Jenkins** - Declarative and Scripted pipelines with security plugins
- **GitLab CI/CD** - YAML-based pipelines with security templates
- **GitHub Actions** - Reusable workflows for security scanning
- **CircleCI** - Orbs and jobs for security orchestration
- **Azure Pipelines** - YAML pipelines with security task groups
- **Bitbucket Pipelines** - YAML-based CI/CD with native security integrations

## 🔒 Security Scanning Features

### Static Application Security Testing (SAST)
- **SonarQube** - Multi-language code quality and vulnerability analysis
- **Semgrep** - Fast, customizable static analysis
- **GitLab SAST** - Native SAST scanning
- **GitHub CodeQL** - Semantic code analysis

### Software Composition Analysis (SCA)
- **Snyk** - Dependency vulnerability detection and remediation
- **Dependabot** - GitHub-integrated dependency updates
- **Trivy** - Lightweight vulnerability scanning for dependencies

### Dynamic Application Security Testing (DAST)
- **OWASP ZAP** - Open source web application scanner
- **Burp Suite** - Enterprise web security testing

### Secret Detection
- **TruffleHog** - Multi-regex secret scanning
- **Gitleaks** - Git secret scanning and remediation

### Infrastructure as Code (IaC) Scanning
- **Terraform** - Policy as code with Sentinel and OPA
- **CloudFormation** - Template validation and compliance checking
- **Kube-bench** - CIS Kubernetes Benchmark verification
- **Checkov** - Infrastructure code scanning
- **Tfsec** - Terraform static analysis
- **Conftest** - Policy testing framework

### Container Security
- **Docker Image Scanning** - Vulnerability detection in base images
- **Trivy** - Container image and filesystem scanning
- **Anchore Grype** - Container image vulnerability scanner
- **Image Signing** - Cosign for container image provenance
- **Registry Scanning** - Continuous scanning of container registries
- **Runtime Security** - Falco for runtime threat detection

## 🛠 Demo Application

For the demonstration of all pipelines, we will be using the [Damn Vulnerable NodeJS Application (DVNA)](https://github.com/appsecco/dvna) . This application serves as a practical example to showcase the security features integrated into our CI/CD pipelines.

## ⚙️ Pipeline Features

### Quality Gates
- ✅ **Critical Severity**: Pipeline fails automatically
- ⚠️ **High Severity**: Creates tickets and requires approval
- 📝 **Medium Severity**: Creates tracking tickets with notifications
- ℹ️ **Low Severity**: Logged for trend analysis

### Issue Tracking Integration
- **Jira**: Automatic ticket creation with severity mapping
- **GitHub Issues**: Native issue management
- **GitLab Issues**: Integrated issue tracking
- **Azure Boards**: Work item creation and linking
- **Linear**: Modern issue tracking integration

### Notification Channels
- **Slack**: Real-time alerts with formatting and threading
- **Email**: HTML reports with actionable recommendations
- **Webhooks**: Custom integrations with external systems
- **Microsoft Teams**: Native Teams notifications
- **Splunk**: Centralized security event logging

## 📁 Repository Structure

```
.
├── jenkins/                    # Jenkins pipeline configurations
│   ├── Jenkinsfile.declarative
│   ├── Jenkinsfile.scripted
│   └── shared-libraries/
├── gitlab/                     # GitLab CI/CD pipeline files
│   ├── .gitlab-ci.yml
│   └── includes/
├── github/                     # GitHub Actions workflows
│   ├── workflows/
│   │   ├── sast.yml
│   │   ├── sca.yml
│   │   ├── dast.yml
│   │   └── container-security.yml
│   └── actions/
├── circleci/                   # CircleCI configurations
│   ├── config.yml
│   └── orbs/
├── azure-pipelines/            # Azure Pipelines YAML
│   ├── azure-pipelines.yml
│   └── templates/
├── aws-codepipeline/           # AWS CodePipeline configurations
│   └── buildspec.yml
├── terraform/                  # IaC scanning examples
│   ├── security-policies/
│   └── examples/
├── docker/                     # Container security examples
│   ├── Dockerfile
│   ├── scanning-config/
│   └── signing/
├── kubernetes/                 # K8s security policies
│   ├── pod-security/
│   ├── network-policies/
│   └── rbac/
├── scripts/                    # Utility and helper scripts
│   ├── notify.sh
│   ├── create-tickets.sh
│   ├── scan-results-parser.sh
│   └── policy-checker.sh
├── policies/                   # Security policy definitions
│   ├── opa-policies/
│   ├── sentinel-policies/
│   └── custom-policies/
├── docker-compose.yml          # Local testing environment
└── README.md                   # This file
```

## 🚀 Quick Start

### Local Testing with Docker Compose

```bash
# Start security scanning services locally
docker-compose up -d

# Run a sample scan
./scripts/run-local-scan.sh

# View results
curl http://localhost:9000  # SonarQube
curl http://localhost:8080  # Jenkins (if enabled)
```

### GitHub Actions Example

```yaml
name: Security Scanning Pipeline

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: SAST Scan
        uses: github/codeql-action/analyze@v2
      
      - name: SCA Scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      
      - name: Container Scan
        uses: aquasecurity/trivy-action@master
      
      - name: Create Tickets
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            // Automatic issue creation logic
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('SAST Scan') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner'
                }
            }
        }
        
        stage('SCA Scan') {
            steps {
                sh 'snyk test --severity-threshold=high'
            }
        }
        
        stage('Quality Gate') {
            steps {
                script {
                    def qg = waitForQualityGate()
                    if (qg.status != 'OK') {
                        error "Pipeline failed due to quality gate failure"
                    }
                }
            }
        }
    }
    
    post {
        always {
            junit 'test-results/**/*.xml'
            publishHTML(target: [reportDir: 'coverage', reportFiles: 'index.html'])
        }
        failure {
            sh './scripts/create-tickets.sh'
            sh './scripts/notify.sh failure'
        }
    }
}
```

## 📊 Supported Severity Levels and Actions

| Severity | Pipeline Action | Ticket Creation | Notification |
|----------|-----------------|-----------------|--------------|
| Critical | ❌ FAIL | Yes | Yes (Urgent) |
| High     | ⏸️ PAUSE | Yes | Yes (High) |
| Medium   | ✅ PASS | Yes | Yes (Normal) |
| Low      | ✅ PASS | No | Dashboard only |

## 🔐 Security Best Practices Implemented

- ✅ Secrets management with vault integration
- ✅ Artifact signing and verification
- ✅ Role-based access control (RBAC)
- ✅ Audit logging for all security events
- ✅ Immutable infrastructure principles
- ✅ Least privilege principle enforcement
- ✅ Defense in depth across pipeline stages
- ✅ Compliance with industry standards (CIS, NIST, PCI-DSS)

## 🛠️ Configuration Requirements

### Required Environment Variables
```bash
# Scanning Tools
SONARQUBE_TOKEN=your_sonarqube_token
SNYK_TOKEN=your_snyk_token
TRIVY_SEVERITY=CRITICAL,HIGH

# Issue Tracking
JIRA_URL=https://your-jira.atlassian.net
JIRA_TOKEN=your_jira_token
GITHUB_TOKEN=your_github_token

# Notifications
SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

## 📚 Documentation

- [Jenkins Pipeline Guide](docs/jenkins-setup.md)
- [GitLab CI/CD Setup](docs/gitlab-setup.md)
- [GitHub Actions Workflows](docs/github-actions.md)
- [Security Policies Reference](docs/policies.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request with clear descriptions

## 📜 License

- to be added

## ⚠️ Disclaimer

These examples are provided as educational resources. Before using in production, ensure all configurations are reviewed and customized for your organization's security requirements and compliance standards.

## 📞 Support & Community

- **Issues**: Report bugs and request features via GitHub Issues
- **LinkedIn**: Connect with us at [MuhammedAliSh](https://www.linkedin.com/in/muhammedalish)

---

**Last Updated**: January 2026
**Maintainers**: MuhammedAliSh