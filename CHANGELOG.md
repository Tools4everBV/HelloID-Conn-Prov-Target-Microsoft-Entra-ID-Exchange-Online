# Change Log

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com), and this project adheres to [Semantic Versioning](https://semver.org).

## [1.2.2] - 28-10-2025

### Authentication methods
- Fixed: Changed only boolean names back to onlySetMobileWhenEmpty and onlySetEmailWhenEmpty
- Fixed: Changed a true/false bug in the processing logic of these booleans
- Fixed: Changed dryRun and actionMessages so that the changed attribute value is shown
- Fixed: Changed dryRun and actionMessages so it doesn't use the Permission.displayName as this doesn't work in the dryRun

## [1.2.1] - 14-10-2025

### Changed
- Fixed: Granting already granted permissions no longer results in an error.
- Fixed: Retrieving security groups.
- Fixed: `Update` action does no longer result in an error when no ExchangeOnline properties are required to be updated.
- Fixed: `Update` action now supports the switch between primary and alias.
- Fixed: `UniquenessCheck` now supports the issue that occurred when mailbox was created but the `Create` action fails.
- Fixed: Issue in the PhoneAuthenticationMethod where the `Grant` and `Revoke` looked up the wrong permission property.
- Fixed: Actions in `Grant` and `Revoke` for email and phone authenticationMethods now work correctly.
- Improvements to the `Readme`.

### Removed
- Removed: displayName from the `UniquenessCheck` script.

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
