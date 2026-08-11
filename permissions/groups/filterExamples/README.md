# Filter Examples

This folder contains example import scripts that filter group memberships by user type.

## Purpose

The goal is to retrieve memberships based on filtered users, so you can run separate Entra ID connectors for **Member** and **Guest** accounts without overlapping accounts and memberships.

## Included scripts

- `importOnlyMemberGroups.ps1`: Imports memberships where the related user is a **Member**.
- `importOnlyGuestGroups.ps1`: Imports memberships where the related user is a **Guest**.

Use these scripts as examples and adapt the filter logic to your own connector setup.
