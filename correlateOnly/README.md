# Correlate only mode

## Table of contents

- [Correlate only mode](#correlate-only-mode)
  - [Table of contents](#table-of-contents)
  - [When to use this mode](#when-to-use-this-mode)
  - [Setting up the target system](#setting-up-the-target-system)
  - [What this mode does (and does not) do](#what-this-mode-does-and-does-not-do)
  - [Limitations compared to the full CRUD connector](#limitations-compared-to-the-full-crud-connector)
  - [Adding regular lifecycle scripts (update, enable, disable, delete)](#adding-regular-lifecycle-scripts-update-enable-disable-delete)
  - [Keeping read-only fields in sync with a None mapping](#keeping-read-only-fields-in-sync-with-a-none-mapping)

## When to use this mode

Use this mode when accounts in Microsoft Entra ID are already created and maintained elsewhere, for example an on-premises Active Directory synced to Entra ID through Microsoft Entra Connect, AADConnect or DirSync.

HelloID then only needs to:
- Correlate existing Entra ID accounts to persons.
- Import them, so permissions and entitlements can still be managed through HelloID.

Creating, updating, enabling, disabling or deleting the account itself is not needed.

## Setting up the target system

Create a **separate** target system in HelloID and only import the files from this `correlateOnly/` folder:

- `configuration.json`
- `create.ps1`
- `fieldMapping.json`
- `import.ps1`

Do not combine these files with the `create.ps1`, `configuration.json`, `fieldMapping.json` or `import.ps1` from the root of the repository, they are not compatible with each other.

The `configuration.json` in this folder only contains the connection settings required to query Microsoft Entra ID (Organization, TenantID, AppID and certificate). Options such as `exchangeOnlineIntegration`, `deleteAccount`, `setManagerOnCreate` and `updateManagerOnUpdate` are not present, as they are not applicable in this mode.

Next, configure the scripts from the [`permissions/`](../permissions/) folder for the entitlements you need, e.g. group memberships. These are the same scripts used for the full CRUD connector, there is no correlate only variant.

## What this mode does (and does not) do

- `create.ps1` does **not** create a new account. It looks up an existing account in Microsoft Entra ID using the configured [correlation configuration](../README.md#correlation-configuration) and correlates it to the person. If no account, or more than one account, is found, the action fails.
- `import.ps1` imports the correlated accounts, so they are visible for entitlement/permission assignment and reconciliation.
- `fieldMapping.json` only maps `id` (used as the account reference), `employeeId` (used for correlation) and `userPrincipalName`. All mappings use the `None` mapping mode, meaning the values are only read from Entra ID and stored in HelloID, they are never written back.
- There is no `update.ps1`, `enable.ps1`, `disable.ps1` or `delete.ps1` in this folder, since account lifecycle changes are typically handled by the source that manages the account in Entra ID (e.g. on-premises AD). These regular scripts from the root of the repository are optional and can be added to the same target system when needed, see [Adding regular lifecycle scripts](#adding-regular-lifecycle-scripts-update-enable-disable-delete).
- Permission scripts in the [`permissions/`](../permissions/) folder can still be used on top of a correlate only target system, since they only require the account reference produced by `create.ps1`.

## Limitations compared to the full CRUD connector

| Aspect                    | Correlate only                                              | Full CRUD (root of the repository)                         |
| ------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Create account            | ❌ Not supported, the account must already exist              | ✅ Creates the account in Entra ID (and optionally Exchange Online) |
| Update account            | ⚠️ Optional, not added by default, see [Adding regular lifecycle scripts](#adding-regular-lifecycle-scripts-update-enable-disable-delete) | ✅ Supported                                                   |
| Enable/Disable account    | ⚠️ Optional, not added by default, see [Adding regular lifecycle scripts](#adding-regular-lifecycle-scripts-update-enable-disable-delete) | ✅ Supported                                                   |
| Delete account            | ❌ Not supported for AD synced accounts, see [Adding regular lifecycle scripts](#adding-regular-lifecycle-scripts-update-enable-disable-delete) | ✅ Supported                                                   |
| Exchange Online           | ❌ Not supported                                               | ✅ Supported (optional)                                        |
| Permissions/entitlements  | ✅ Supported                                                   | ✅ Supported                                                   |
| Import                    | ✅ Supported                                                   | ✅ Supported                                                   |

## Adding regular lifecycle scripts (update, enable, disable, delete)

The `update.ps1`, `enable.ps1`, `disable.ps1` and `delete.ps1` scripts from the root of the repository work with a correlate only target system: add them to the same target system alongside `create.ps1` and `import.ps1` from this folder.

This is useful when you need to manage a **cloud-only** attribute that isn't synchronized from your on-premises AD, for example `ageGroup`. This only works for properties that aren't driven by the AD sync, e.g. `employeeHireDate` can **not** be managed this way, since Microsoft Entra Connect will overwrite it again with the value from AD on the next sync. Only map properties in `fieldMapping.json` that are actually cloud-only.

`enable.ps1` and `disable.ps1` also work, but for AD synced accounts, keep in mind that a following Microsoft Entra Connect sync cycle will overwrite `accountEnabled` again with the value from AD.

`delete.ps1` does **not** work for AD synced accounts: Microsoft Entra ID rejects the delete call outright for accounts that are managed through directory synchronization. Deleting an AD synced account must be done by removing it in the source AD.

## Keeping read-only fields in sync with a None mapping

Fields mapped with the `None` mapping mode also work when the regular `update.ps1` is added to a correlate only target system, as described above. When `Store in account data` is enabled for that field, HelloID reads the current value from Microsoft Entra ID during an update and stores it, without writing anything back to Entra ID.

This is useful when a field is fully managed outside of HelloID, but you still want its current value visible on the person's **Accounts** tab in HelloID. For example: `userPrincipalName` is changed in AD, which is synced to both Microsoft Entra ID and the source system. Without a None mapping for `userPrincipalName` on the update action, HelloID keeps showing the old UPN in the stored account data. With the None mapping configured, the next time an update action runs for the account, HelloID reads the current UPN from Microsoft Entra ID and updates the stored account data, without writing anything back to Entra ID.

> [!NOTE]
> HelloID is source driven and only executes an update action when it detects a change in the source data for a mapped field. The value is only refreshed when such an update is processed for the account, not in real time when the value changes in Entra ID itself.

