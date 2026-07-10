# Microsoft Teams Channels

## Supported features

The following features are available:

| Feature                                   | Supported | Actions                             | Remarks            |
| ----------------------------------------- | --------- | ----------------------------------- | ------------------ |
| **Account Lifecycle**                     | ✅         | Correlate                           |                    |
| **Permissions**                           | ✅         | Retrieve, Grant, Revoke             | Static             |
| **Resources**                             | ❌         | -                                   |                    |
| **Entitlement Import: Permissions**       | ✅         | -                                   |                    |
| **Governance Reconciliation Resolutions** | ✅⚠️       | -                                   |                    |

### ⚠️ Governance Reconciliation Resolutions

Governance reconciliation is supported for permissions only. Accounts are dependent on the use of the Entra ID connector

# HelloID-specific configuration

Once you have completed the Microsoft setup and followed their best practices, configure the following HelloID-specific requirements.

- **API Permissions** (Application permissions):
  - `User.ReadWrite.All`
  - `GroupMember.ReadWrite.All`
  - `Team.ReadBasic.All`
  - `TeamMember.ReadWrite.All`
  - `ChannelMember.ReadWrite.All`

## Remarks

### Members of private channels

You can only add a member to a private channel once it's member of the team of which the channel is part of. Team memberships can be provisions using the default group memberships. Once there is no order in which permissions will be provisioned. You can get an error that the user is not member of the team when they get provisioned in the same enforcement.

## Development resources

### API endpoints

The following endpoints are used by the connector

| Endpoint                           | Description                                                  |
| ---------------------------------- | ------------------------------------------------------------ |
| /groups                            | Retrieve teams                                               |
| /teams/{teamId}/channels           | Retrieve channels and members                                |
