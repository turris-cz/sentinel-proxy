# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- log czmq with logc_czmq
- device token unit tests
- list of times of last received messages for each topic

## Removed
- dev folder

## Fixed
- device token library - inputs checks
- runnig unit tests in valgrind in no fork mode
- autotools warnings

## [2.0.0] - 2022-12-30
### Added
- logc - logging support
- connected ZMQ peers monitoring
- check - unit tests
- cppcheck - linting
- lcov - code coverage
- valgrind
- Gitlab CI
- pkg-config and version scripts for device token library
- more fields in configuration file - it can hold the whole config now
- manual overall tests

### Changed
- split server CLI option to server and port options
- CLI options - names, arguments and their descriptions updated

## [1.4] - 2021-05-31
### Added
- Sending status messages to server
- Error messages

### Removed
- Data compression

## [1.3.1] - 2021-02-01
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
