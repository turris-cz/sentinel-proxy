# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- Testing proxy - moved from Minipots repository
- CHANGELOG

### Changed
- Complete code refactoring - replace `zpoller` by `zloop`

## [1.3] - 2020-02-24
### Added
- Device token library

### Changed
- Use unified device token check

### Fixed
- Device token string in configuration file

## [1.2.1] - 2020-02-19
### Fixed
- MQTT segfault

## [1.2] - 2020-02-19
### Changed
- Configuration parsing moved to separate file
- CLI options parsing replaced by `argp` instead `getopt`
- MQTT topic preparation moved to separate function

### Added
- Using configuration file
- Build instructions in README
- Send device token

## [1.1] - 2019-04-09
### Fixed
- MQTT topic composing
- MQTT client passing

### Changed
- Default CA file name
- Used common name instead of alternative name in client certificate 

## [1.0] - 2019-04-09
Initial release
