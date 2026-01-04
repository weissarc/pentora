# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-01-04

### Added
- HTTP security headers analysis with scoring and recommendations ([74737a2](74737a2))
  - Parse HSTS, CSP, X-Frame-Options, X-Content-Type-Options headers
  - Calculate security score (0-100) based on header presence
  - Generate recommendations for missing security headers
- `--targets` flag for flexible target specification ([95e1adf](95e1adf))
  - Support multiple formats: `-t IP1,IP2` or `-t IP1 -t IP2`
  - Merge flag targets with positional arguments
  - Maintain backward compatibility
- UDP port discovery module ([d4a2fd1](d4a2fd1))
  - Protocol-specific payloads for DNS, SNMP, NTP, Syslog, UPnP
  - ICMP unreachable detection for filtered ports
  - Auto-registration with module factory
- ConfigSource interface for extensible configuration ([2ef2465](2ef2465))
  - Support for environment variables with `VULNTOR_*` prefix
  - Pluggable source system with priority ordering
  - Built-in sources: Default, File, Env, Flag
- XDG Base Directory Specification support for plugin cache ([aed8286](aed8286))

### Fixed
- Configuration file loading now errors when explicit `--config` file not found ([7113519](7113519))
  - Silent skip only for default/empty paths
  - Required field added to FileSource

### Removed
- **SECURITY**: Removed `dev_mode` authentication bypass backdoor ([f0a65ef](f0a65ef))
- Unused `BindServerFlags` function and related tests ([f0a65ef](f0a65ef))
- `config` command from root CLI ([320aa71](320aa71))

### Changed
- Refactored configuration loading to use source-based architecture ([2ef2465](2ef2465))

## [0.1.0-rc.2] - Previous Release

Initial release candidate with core scanning capabilities.

[Unreleased]: https://github.com/vulntor/vulntor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/vulntor/vulntor/compare/v0.1.0-rc.2...v0.2.0
[0.1.0-rc.2]: https://github.com/vulntor/vulntor/releases/tag/v0.1.0-rc.2
