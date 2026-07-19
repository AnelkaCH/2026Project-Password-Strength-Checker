# Changelog

All notable changes to this project will be documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Planned
- HaveIBeenPwned API integration for breach checking
- Entropy-based scoring
- Dictionary word detection
- Password generation suggestions
- GUI version

## [2026-07-19] - Version 1.0.3

### Added
- CHANGELOG.md with full version history
- ARCHITECTURE.md explaining system design and decisions

### Changed
- Rewrote README.md to follow standard project documentation structure

### Removed
- Personal profile content that was duplicated in README.md
- Template files (README_template, CHANGELOG_template, ARCHITECTURE_template)

## [2026-07-14] - Version 1.0.2

### Added
- Feedback suggestion when password is shorter than 16 characters

### Fixed
- Naming bug in feedback output

## [2026-07-08] - Version 1.0.1

### Added
- More common password patterns to the detection list (passw0rd, qwerty123, 1q2w3e4r, 111111, 000000, asdfghjkl, user, guest)

## [2025-06-25] - Version 1.0.0

### Added
- Password scoring on a 0–100 scale
- Strength rating system (Very Weak, Weak, Moderate, Strong, Very Strong)
- Length-based scoring (up to 30 points)
- Character variety scoring: uppercase, lowercase, digits, symbols (up to 40 points)
- Common weak password pattern detection with penalty scoring
- Personalized feedback and improvement suggestions
- CLI interface for interactive use
