# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).


## [1.2.0] - 10-07-2025

### Added
- Added support for reconciliation actions on unmanaged accounts.
- Added notification support for `enable`, `disable`, and `delete` actions (Data vs PreviousData).

### Changed
- Optimized field mapping to store less accountData.
- Fixed: ActionMessage in the delete script.
- Fixed: Boolean comparisons in the `Update`, `Disable`, and `Delete` scripts.
- Fixed: Get user in the disable script.
- Fixed: Missing audit logging for Entra updates in the disable script.


## [1.1.0] - 12-06-2025

### Added
- Permissions functionality added, based on existing permissions in the target system. The following permissions are available:
 - Groups
 - Licenses
 - Phone authentication methods
 - Email authentication methods

Note that for both groups and licenses, the _import_ feature is also supported.

## [1.0.0] - 15-03-2025

This is the first official release of _HelloID-Conn-Prov-Target-MS-Entra-Exo_. This release is based on template version _v2.0.1_.

### Added

### Changed

### Deprecated

### Removed
