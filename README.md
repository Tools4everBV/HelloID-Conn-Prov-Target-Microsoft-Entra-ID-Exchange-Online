# HelloID-Conn-Prov-Target-MS-Entra-Exo

> [!WARNING]
> The _HelloID-Conn-Prov-Target-MS-Entra-Exo_ is currently a __private__ repository because the _Microsoft Exchange Online_ functionality is controlled by a _feature flag_.  If you’d like to use this connector, please contact your account manager.

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.

<p align="center">
  <img src="https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-EntraID/blob/main/Logo.png?raw=true">
</p>

## Table of contents

- [HelloID-Conn-Prov-Target-MS-Entra-Exo](#helloid-conn-prov-target-ms-entra-exo)
  - [Table of contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Private repository](#private-repository)
  - [Supported  features](#supported--features)
  - [Getting started](#getting-started)
    - [Prerequisites](#prerequisites)
      - [App Registration](#app-registration)
      - [Creating a new app registration](#creating-a-new-app-registration)
      - [Configuring permissions](#configuring-permissions)
      - [Authentication and Authorization](#authentication-and-authorization)
      - [Certificate](#certificate)
    - [Connection settings](#connection-settings)
    - [Correlation configuration](#correlation-configuration)
    - [Field mapping](#field-mapping)
  - [Remarks](#remarks)
    - [Correlation value](#correlation-value)
      - [Fallback property (ExO only)](#fallback-property-exo-only)
      - [properties without the `exchangeOnline` prefix](#properties-without-the-exchangeonline-prefix)
      - [Hardcoded boolean values](#hardcoded-boolean-values)
      - [Hardcoded mapping](#hardcoded-mapping)
    - [`updateManagerOnUpdate` can be deleted](#updatemanageronupdate-can-be-deleted)
    - [ExO PowerShell module](#exo-powershell-module)
    - [`Connect-ManagedExchangeOnline`](#connect-managedexchangeonline)
    - [Script flow](#script-flow)
      - [1. Preparation](#1-preparation)
      - [2. Correlation Check](#2-correlation-check)
      - [3. Exchange Online Mailbox Check (if enabled)](#3-exchange-online-mailbox-check-if-enabled)
      - [4. Manager Lookup (if configured)](#4-manager-lookup-if-configured)
      - [5. Determine Actions](#5-determine-actions)
      - [6. Execute Actions](#6-execute-actions)
  - [Development resources](#development-resources)
    - [GraphAPI documentation](#graphapi-documentation)
    - [ExO documentation](#exo-documentation)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction

_HelloID-Conn-Prov-Target-MS-Entra-Exo_ is a _target_ connector. _MS-Entra-Exo_ provides a set of REST API's that allow you to programmatically interact with its data.

The _HelloID-Conn-Prov-Target-MS-Entra-Exo_ connector supports both _Microsoft Entra_ combined with _Microsoft Exchange Online_, as well as standalone _Microsoft Entra_ environments. Integration with _Exchange Online_ can be enabled via the configuration by toggling the `Exchange Online integration` option.

> [!NOTE]
> When using _MS Exchange Online_, note that licensing must be configured separately, for example by using group memberships.

## Private repository

The _HelloID-Conn-Prov-Target-MS-Entra-Exo_ is currently a __private__ repository because the _Microsoft Exchange Online_ functionality is controlled by a _feature flag_.
If you’d like to use this connector, please contact your account manager.

## Supported  features

The following features are available:

| Feature                             | Supported | Actions                                 | Remarks |
| ----------------------------------- | --------- | --------------------------------------- | ------- |
| **Account Lifecycle**               | ✅         | Create, Update, Enable, Disable, Delete |         |
| **Permissions**                     | ✅         | -                                       |         |
| **Resources**                       | ❌         | -                                       |         |
| **Uniqueness**                      | ❌         | -                                       |         |
| **Entitlement Import: Accounts**    | ❌         | -                                       |         |
| **Entitlement Import: Permissions** | ❌         | -                                       |         |

> [!NOTE]
In version _1.0.0_, only user-related actions -such as create, update, and delete— are supported. Permission management will be introduced in a future release.

## Getting started

### Prerequisites

#### App Registration

Before implementing this connector, make sure to configure a Microsoft Entra ID, an **App Registration**.
During the setup process, you’ll create a new App Registration in the Azure portal, assign the necessary API permissions (such as user and group read/write), and generate credentials—either a client secret or a certificate. These credentials are then configured in HelloID to allow the connector to authenticate securely.

This step is essential for enabling HelloID to provision and manage accounts within your Microsoft 365 environment.

#### Creating a new app registration

1. **Navigate to App Registrations**:
   - Open the [Microsoft Entra ID Portal](https://entra.microsoft.com/).
   - Go to **Microsoft Entra ID** > **App registrations**.
   - Click **New registration**.

2. **Register the Application**:
   - **Name**: Choose a name (e.g., `HelloID PowerShell`).
   - **Supported account types**: Select who can use the app (e.g., *Accounts in this organizational directory only*).
   - **Redirect URI**: Choose `Web` and enter a URI (e.g., `http://localhost`).

3. **Complete Registration**:
   - Click **Register** to create the application.

For more details, refer to the official guide: [Quickstart: Register an app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app?tabs=certificate).

#### Configuring permissions

After registration, configure API permissions so the app can interact with Microsoft Graph on behalf of HelloID.

1. Go to the app’s **API permissions** section.
2. Click **Add a permission**.
3. Choose **Microsoft Graph**.
4. Select **Application permissions** and add:
   - `User.ReadWrite.All`
   - `Group.ReadWrite.All`
   - `GroupMember.ReadWrite.All`
   - `UserAuthenticationMethod.ReadWrite.All`
5. Click **Add permissions**.
6. Click **Grant admin consent for [Your Tenant]** if required.

More info: [Configure a client app to access a web API](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-access-web-apis).

#### Authentication and Authorization

To authenticate with the Graph API, you’ll need credentials for your app. The recommended approach is to use a **Client Secret**.

1. **Get the Tenant ID**:
   - Go to **Azure Active Directory** > **Overview**.
   - Copy the **Tenant ID**.

2. **Get the Client ID**:
   - Go to **App registrations**, select your app.
   - Copy the **Application (client) ID**.

3. **Create a Client Secret**:
   - Navigate to **Certificates & secrets** in your app.
   - Under **Client secrets**, click **New client secret**.
   - Enter a description and select an expiration.
   - Click **Add**, and **copy the value immediately**—you won’t be able to see it again.

More info: [Add credentials](https://learn.microsoft.com/en-us/graph/auth-register-app-v2#add-credentials).

#### Certificate

A certificate is required to establish a secure connection to both Microsoft Graph and Exchange Online. A comprehensive guide on how to create a certificate and extract the _Base64_ key is available on our [forum](https://forum.helloid.com/forum/helloid-provisioning/5338-instruction-setting-up-a-certificate-for-microsoft-graph-api-in-helloid-connectors#post5338).

### Connection settings

The following settings are required to connect to the API.

| Setting                    | Description                                                                                                                                               | Mandatory |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| Organization               | Make sure to use the organization's primary `.onmicrosoft.com` domain, as using alternative domains may result in unexpected behavior or inconsistencies. | Yes       |
| TenantID                   | The unique identifier (ID) of the tenant in Microsoft Entra ID.                                                                                           | Yes       |
| AppID                      | The unique identifier (ID) of the App Registration in Microsoft Entra ID                                                                                  | Yes       |
| AppCertificateBase64String | The Base64-encoded string representation of the app certificate                                                                                           | Yes       |
| AppCertificatePassword     | The password associated with the app certificate.                                                                                                         | Yes       |
| exchangeOnlineIntegration  | Indicates whether the Exchange Online integration should be used.                                                                                         | No        |
| deleteAccount              | Delete the account upon revoking the entitlement.                                                                                                         | No        |
| setManagerOnCreate         | Assign a manager when an account is created.                                                                                                              | No        |
| updateManagerOnUpdate      | Update the manager when the account update operation is performed.                                                                                        | No        |

### Correlation configuration

The correlation configuration is used to specify which properties will be used to match an existing account within _MS-Entra-Exo_ to a person in _HelloID_.

| Setting                   | Value                             |
| ------------------------- | --------------------------------- |
| Enable correlation        | `True`                            |
| Person correlation field  | `PersonContext.Person.ExternalId` |
| Account correlation field | `EmployeeId`                      |

> [!TIP]
> _For more information on correlation, please refer to our correlation [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems/correlation.html) pages_.

### Field mapping

The field mapping can be imported by using the _fieldMapping.json_ file.

## Remarks

### Correlation value

Initial correlation is based on the `EmployeeId` with a fall back to `GivenName` and `FirstName`. See also: [Fall back property.](#fallback-property-exo-only)

#### Fallback property (ExO only)

A fallback is necessary because when creating an account using `New-Mailbox`, it’s not possible to immediately set the correlation value.
Therefore, when the account is created, the correlation value (employeeId) is temporarily placed in the `GivenName`/`FirstName` field.
Afterward, a separate action is performed to correctly set the correlation value and restore the `FirstName` to the correct value.

A create of an EXO account consists of 4 or 5 actions:
- `CreateAccountExo`
- `UpdateAccountEntraCorrelationValueAfterCreateMailbox`
- `UpdateAccountExo`
- `UpdateAccountEntra`
- `SetManager` (optional)

`UpdateAccountExo` has a retry mechanism with 5 attempts, because it can happen that the account is not immediately found after it’s created. (This problem does not occur within MS Entra).

If one of these individual action fails, the entire create operation fails. During a retry, a normal correlation attempt is first made. If no match is found, the script tries to find the account based on the `FirstName`, where the correlation value was temporarily stored earlier. If an account is found using this fallback method, the script treats it as a create operation rather than a correlate. It then performs the same actions as a regular create, except for executing `New-Mailbox`.

Fall back must be configured within the _create_ lifecycle action.

```powershell
# Script Configuration, only Required for ExchangeOnlineIntegration.
# Note that the property name should be the same! The givenName in Entra corresponds to FirstName in EXO.
$entraMailboxFallbackLookupProperty = 'givenName'
$exchangeMailboxFallbackLookupProperty = 'FirstName'
```

#### properties without the `exchangeOnline` prefix

Mapped properties without the `exchangeOnline` prefix are updated through _GraphAPI_.

#### Hardcoded boolean values

In the field mapping, we use one example property: `HiddenFromAddressListsEnabled`. This property is a boolean, and its value is hardcoded in the code for conversion.
**Note:** `Set-Mailbox` does **not** accept a string like "true" as a valid boolean value.

When adding an Exchange property to the field mapping, you will need to update the code to convert the string to a boolean. (It might be possible to make this conversion dynamic in the future.)

#### Hardcoded mapping

To create an EXO account, a hardcoded mapping is used in the code. This ensures consistency in the field mapping by following the field names of the Graph API. Without this, you would encounter duplicate mappings with identical values.

The code example below demonstrates this mapping:

```powershell
$createExoAccountSplatParams = @{
    Alias                     = $actionContext.Data.mailNickName
    Name                      = $actionContext.Data.displayName
    PrimarySmtpAddress        = ($actionContext.Data.exchangeOnline.emailAddresses | Where-Object { $_ -cmatch '^SMTP:' } | Select-Object -First 1) -replace 'SMTP:', ''
    MicrosoftOnlineServicesID = $actionContext.Data.userPrincipalName
    ResetPasswordOnNextLogon  = [bool]($actionContext.Data.passwordProfile.forceChangePasswordNextSignIn)
    Password                  = ConvertTo-SecureString -String $actionContext.Data.passwordProfile.password -AsPlainText -Force
}
```

### `updateManagerOnUpdate` can be deleted

The `updateManagerOnUpdate` switch can potentially be removed by simply checking the `managerId`. If it is not mapped in the update, we do not perform the action. This simplifies the process by eliminating the need for an explicit switch to control whether the manager update is applied.

### ExO PowerShell module

Within HelloID, version _3.5.1_ of the Exchange Online module is being used. https://www.powershellgallery.com/packages/ExchangeOnlineManagement/3.5.1

### `Connect-ManagedExchangeOnline`

The connector depends on the `Connect-ManagedExchangeOnline` cmdlet. Note that this cmdlet is __not available__ on your local machine.

### Script flow

#### 1. Preparation

- Enables TLS 1.2 for secure HTTPS communication.
- Defines fallback properties for mailbox correlation between Entra and Exchange Online.

#### 2. Correlation Check

- Attempts to find an existing Entra account using a configured correlation field and value.
- If not found, attempts to locate the account using a fallback property (e.g., `givenName`).
- If multiple accounts are found in either step, the process fails.

#### 3. Exchange Online Mailbox Check (if enabled)

- If an Entra account is found, the script attempts to locate the associated Exchange Online mailbox using the `ExternalDirectoryObjectId`.
- If the mailbox is not found, and Exchange Online integration is required, an exception is thrown.

#### 4. Manager Lookup (if configured)

- If `setManagerOnCreate` is enabled and a `ManagerAccount` reference is provided, it attempts to validate the manager's existence.
- If the manager account is not found (404), an exception is thrown.

#### 5. Determine Actions

- Based on account presence in Entra and ExO, determines the required actions:
  - **Entra only**: Create or correlate Entra account.
  - **Entra + ExO**: Create Exchange mailbox, update correlation value in Entra, update both Entra and ExO accounts.
  - **SetManager**: If required and configured.

#### 6. Execute Actions

Actions are executed in order:
- `CreateAccountEntra`: Creates the MS Entra account.
- `CreateAccountExo`: Creates an Exchange Online mailbox and sets the fallback property for Entra.
- `UpdateAccountEntraCorrelationValueAfterCreateMailbox`: Updates the Entra account with the correlation value after mailbox creation.
- `UpdateAccountEntra`: Updates user properties in the Entra account (excluding ExchangeOnline and passwordProfile).
- `UpdateAccountExo`: Updates mailbox properties in Exchange Online, with special handling to skip no-op updates.
- `CorrelateAccount`: Correlates both the MS Entra and Exchange Online account(s).
- `SetManager`: Placeholder for setting manager relationship, not implemented.

## Development resources

### GraphAPI documentation

The following endpoints are used by the connector

| Endpoint | Description               |
| -------- | ------------------------- |
| /Users   | Retrieve user information |

### ExO documentation

The following cmdlets are used by the connector

| Cmdlet | Description               |
| ------ | ------------------------- |
| /Users | Retrieve user information |

## Getting help

> [!TIP]
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/en/provisioning/target-systems/powershell-v2-target-systems.html) pages_.

> [!TIP]
>  _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_.

## HelloID docs

The official HelloID documentation can be found at: https://docs.helloid.com/
