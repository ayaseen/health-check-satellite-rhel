# RHEL & Satellite Health Check Tool

A comprehensive health check utility for Red Hat Enterprise Linux and Red Hat Satellite servers to identify issues and provide actionable recommendations.

![health-check-demo](images/rhel-check.gif)

## Overview

This Go application performs thorough health checks on RHEL and Satellite systems to identify issues, misconfigurations, and performance bottlenecks. The tool executes more than 40 specialized checks across multiple categories and generates detailed reports with color-coded status indicators and recommendations.

### RHEL Checks Categories

- **System Information**: OS version, registration status, hostname resolution, system uptime
- **Time Settings**: Time synchronization, NTP/chronyd configuration, timezone settings, clock drift
- **Memory Management**: Memory usage, swap configuration, memory pressure stats, OOM events
- **Storage & Disks**: Disk usage, filesystem health, I/O performance, mount points, filesystem quotas
- **Performance**: CPU utilization, load averages, process resource consumption, system tuning parameters
- **Networking**: Interface configuration, routing tables, firewall rules, connectivity tests
- **Security**: Security policies, SELinux configuration, system users, SSH settings, security updates
- **Service Management**: Service health, boot issues, systemd targets, failed services
- **Logging**: Log analysis, log rotation configuration, system events, error patterns
- **Package Management**: Package integrity, update status, repository configuration, dependency issues
- **Authentication**: Authentication mechanisms, LDAP/IPA integration, user management
- **Backup & Recovery**: Backup configuration, recovery points, disaster recovery readiness
- **Kernel Configuration**: Kernel parameters, loaded modules, BIOS/firmware versions, boot configuration
- **Advanced Storage**: Storage layout, LVM configuration, multipath settings, performance considerations

### Satellite Checks Categories

- **System Status**: Satellite version, installation type, lifecycle environment, system resources
- **Storage Layout**: Pulp content storage, MongoDB storage, PostgreSQL storage, filesystem layout
- **Database Health**: PostgreSQL health, Candlepin DB, Foreman DB, MongoDB performance, database tuning
- **Content Management**: Repository synchronization, content views, publication history, composite views
- **Capsule Servers**: Capsule health, content synchronization, certificate status, server communication
- **Performance Tuning**: Service performance metrics, resource allocation, tuning recommendations
- **Security Posture**: SSL certificates, authentication mechanisms, role-based access control, compliance
- **Task Management**: Task queue health, failed tasks, task scheduling, cleanup processes
- **Backup Procedures**: Backup configuration, scheduled backups, backup integrity, restoration procedures
- **Monitoring Setup**: Logging configuration, monitoring integrations, alert settings, key metrics
- **Configuration Analysis**: Server parameters, custom settings, environment variables
- **Subscription Status**: Allocation, manifest status, subscription utilization, capacity management
- **Host Management**: Registration status, errata applicability, content host health
- **Synchronization Plans**: Configuration, schedule status, execution history
- **Virt-Who Integration**: Configurations, hypervisor reporting, subscription status

## Prerequisites

- Red Hat Enterprise Linux 8, 9 or later version
- Root/sudo access for complete check coverage
- Golang 1.20+

## Installation

Clone the repository and build the application:

```bash
git clone https://github.com/ayaseen/healthCheck-satellite-rhel.git
cd healthCheck-satellite-rhel
./build.sh
```

The `build.sh` script will create a binary named `health-check` in the current directory.


## Usage

Run the health check with root privileges for full functionality:

```bash
sudo ./health-check --parallel
```

The tool automatically detects whether it's running on RHEL or Satellite and performs the appropriate checks.

### Command Examples

Run only RHEL checks:
```bash
sudo ./health-check rhel
```

Run Satellite checks without RHEL checks:
```bash
sudo ./health-check satellite --skip-rhel
```

Run only specific check categories:
```bash
sudo ./health-check --include storage,security,performance
```


### Command-line Options

#### Global Flags
- `-h, --help`: Display help information
- `-o, --output string`: Output file path (default is auto-generated)
- `-v, --verbose`: Enable detailed output during check execution
- `-p, --parallel`: Run checks in parallel (default true)
- `-s, --skip stringSlice`: Categories to skip (e.g., "network,security")
- `-i, --include stringSlice`: Only run specified categories
- `-t, --timeout int`: Timeout in seconds for individual checks (default 30)
- `--compress-password string`: Password-protect the report archive

#### RHEL Command Flags
- `--skip-network`: Skip network-related checks
- `--skip-performance`: Skip performance-related checks

#### Satellite Command Flags
- `--skip-rhel`: Skip RHEL health checks
- `--skip-content-sync`: Skip content synchronization checks
- `--skip-host`: Skip host management checks
- `--skip-sync-plans`: Skip sync plan checks
- `--skip-virtwho`: Skip virt-who configuration checks
- `--organization string`: Organization to check (checks all if not specified)

## Reports

The tool generates comprehensive reports in AsciiDoc format. Reports include:

- Color-coded status indicators (critical, warning, info, ok)
- Executive summary of system health
- Detailed analysis of each check category
- Specific observations and recommendations
- Reference links to Red Hat documentation

Reports are saved in the `reports` directory by default with the naming convention. The main report file is protected with a password ("7e5eed48001f9a407bbb87b29c32871b") for security:
```
<hostname>-<type>-health-check-<timestamp>.adoc
```

Example:
```
satellite01-satellite-health-check-20230515-142015.adoc
```

## Check Details

Each check evaluates a specific aspect of the system and provides:

1. **Status**: Critical, Warning, Info, or OK
2. **Description**: What the check examines
3. **Observations**: What was found during the check
4. **Recommendations**: Suggested actions to resolve issues
5. **References**: Links to relevant documentation

The checks are designed to detect common issues, misconfigurations, and performance bottlenecks according to Red Hat best practices.

## Features

- **Auto-detection**: Automatically detects if running on RHEL or Satellite
- **Parallel Execution**: Runs checks in parallel for faster completion
- **Progress Tracking**: Shows progress bar during check execution
- **Categorized Checks**: Organizes checks by functional category
- **Detailed Reports**: Generates comprehensive, color-coded reports
- **Password Protection**: Optionally compress reports with password protection
- **Flexible Configuration**: Select specific check categories to run

***

# Key Questions for RHEL & Satellite Health Check

## Essential Context Questions

### System Role & Criticality

* What is this system's primary role and how critical is it to your business operations?
* Is this system part of a high-availability setup or cluster?


### Recent History

* Have there been any significant changes or issues with this system in the past 30 days?
* Are you currently experiencing any specific problems that prompted this health check?



## RHEL Systems

### Performance

* Have you observed any resource bottlenecks (CPU, memory, I/O) or performance degradation?
* What monitoring solution do you currently use for this system?


### Storage & Backup

* Are you using any specialized storage technologies, and what is your backup strategy?
* Have you experienced any storage-related issues (space constraints, performance, etc.)?


### Security & Authentication

* How do you manage user authentication and what security compliance requirements apply?
* Have you customized any default security settings or hardening policies?


### Maintenance

* What is your patch management strategy and maintenance window for this system?
* How do you handle configuration management across your environment?



## Satellite Servers

### Content Management

* What is your content view strategy and promotion workflow?
* Are there specific content synchronization issues you've encountered?


### Scale & Performance

* How many hosts are managed by this Satellite and what peak loads do you experience?
* Have you performed any custom tuning for your Satellite deployment?


### Integration & Automation

* How do you integrate Satellite with other tools in your environment?
* What automation workflows have you implemented?


### Maintenance Strategy

* What is your upgrade strategy and backup procedure for Satellite?
* How do you manage Satellite maintenance without disrupting operations?


### Capsule Architecture

* How many capsule servers do you have and how are they distributed?
* Have you experienced any issues with capsule server performance or synchronization?



## Post-Assessment Follow-up

### Critical Findings

* Were you aware of these critical issues, and what constraints might prevent immediate remediation?
* What business impact have these issues caused?


### Improvement Prioritization

* Which areas of this health assessment would you like to prioritize for remediation?
* What timeline constraints affect your ability to implement these recommendations?


### Future Planning

* Are there any planned changes to this system's workload or role?
* What future requirements do you anticipate that might affect our recommendations?



## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.

## Author

Amjad Yaseen (ayaseen@redhat.com)

## Disclaimer

This is a diagnostic tool that provides recommendations based on best practices. Always review suggestions carefully before implementing changes in production environments.

> **Note**: For complete and accurate results, run this tool with root/sudo privileges.