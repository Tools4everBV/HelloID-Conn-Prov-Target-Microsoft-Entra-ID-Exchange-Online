##############################################################################
# HelloID-Conn-Prov-Target-MS-Entra-Exo-Permissions-EmailAuthenticationMethods
# PowerShell V2
##############################################################################
# Please see the Microsoft docs on supported email types: https://learn.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-get?view=graph-rest-1.0&tabs=http

$outputContext.Permissions.Add(
    @{
        DisplayName    = "email authentication method - email"
        Identification = @{
            Reference = '3ddfcfc8-9383-446f-83cc-3ab9be4be18f'
        }
    }
)