#################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-Permissions-TeamsChannels-List
# List Channels as permissions
# PowerShell V2
#################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

#region functions

function Resolve-MS-Entra-ExoError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            ScriptLineNumber = $ErrorObject.InvocationInfo.ScriptLineNumber
            Line             = $ErrorObject.InvocationInfo.Line
            ErrorDetails     = $ErrorObject.Exception.Message
            FriendlyMessage  = $ErrorObject.Exception.Message
        }

        try {
            if (-not [string]::IsNullOrEmpty($ErrorObject.ErrorDetails.Message)) {
                $httpErrorObj.ErrorDetails = $ErrorObject.ErrorDetails.Message | ConvertFrom-Json
            }
            elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
                if ($null -ne $ErrorObject.Exception.Response) {
                    $streamReaderResponse = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
                    if (-not [string]::IsNullOrEmpty($streamReaderResponse)) {
                        $httpErrorObj.ErrorDetails = $streamReaderResponse
                    }
                }
            }
            $errorDetailsObject = $httpErrorObj.ErrorDetails
            if ($errorDetailsObject.error_description) {
                $httpErrorObj.FriendlyMessage = $errorDetailsObject.error_description
            }
            elseif ($errorDetailsObject.error.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.code): $($errorDetailsObject.error.message)"
            }
            elseif ($errorDetailsObject.error.details.message) {
                $httpErrorObj.FriendlyMessage = "$($errorDetailsObject.error.details.code): $($errorDetailsObject.details.message)"
            }
            else {
                $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
            }
        }
        catch {
            $httpErrorObj.FriendlyMessage = $httpErrorObj.ErrorDetails
        }
        Write-Output $httpErrorObj
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Certificate
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($actionContext.Configuration.AppId)"
            'sub' = "$($actionContext.Configuration.AppId)"
            'aud' = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Extract the private key from the certificate
        $rsaPrivate = $Certificate.PrivateKey
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        # Sign the JWT
        $signatureInput = "$base64Header.$base64Payload"
        $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Ensure the certificate has a private key
        if (-not $Certificate.HasPrivateKey -or -not $Certificate.PrivateKey) {
            throw "The certificate does not have a private key."
        }

        # Create the JWT token
        $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $actionContext.Configuration.AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($actionContext.Configuration.TenantID)/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        Write-Output $createEntraAccessTokenResponse.access_token
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param()
    try {
        $rawCertificate = [system.convert]::FromBase64String($actionContext.Configuration.AppCertificateBase64String)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $actionContext.Configuration.AppCertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

try {
    # Create authorization headers
    
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Authorization', "Bearer $entraToken")
    $headers.Add('Accept', 'application/json')
    $headers.Add('Content-Type', 'application/json')
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $headers.Add('ConsistencyLevel', 'eventual')

    # Get Microsoft Teams
    # Microsoft docs: https://learn.microsoft.com/en-us/graph/teams-list-all-teams
    $actionMessage = "querying Microsoft Teams"

    $microsoftTeams = [System.Collections.ArrayList]@()
    do {
        $getMicrosoftTeamsSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/groups?`$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&`$select=id,displayName&`$top=999&`$count=true"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false 
            ErrorAction = "Stop"
        }
        if (-not[string]::IsNullOrEmpty($getMicrosoftTeamsResult.'@odata.nextLink')) {
            $getMicrosoftTeamsSplatParams["Uri"] = $getMicrosoftTeamsResult.'@odata.nextLink'
        }

        $getMicrosoftTeamsResult = $null
        $getMicrosoftTeamsResult = Invoke-RestMethod @getMicrosoftTeamsSplatParams
    
        if ($getMicrosoftTeamsResult.Value -is [array]) {
            [void]$microsoftTeams.AddRange($getMicrosoftTeamsResult.Value)
        }
        else {
            [void]$microsoftTeams.Add($getMicrosoftTeamsResult.Value)
        }
    } while (-not[string]::IsNullOrEmpty($getMicrosoftTeamsResult.'@odata.nextLink'))

    Write-Information "Queried Microsoft Teams. Result count: $(($microsoftTeams | Measure-Object).Count)"

    # Get Teams Channels
    $microsoftTeamsChannels = [System.Collections.ArrayList]@()
    foreach ($microsoftTeam in $microsoftTeams) {
        # Get Microsoft Teams Channels
        # Microsoft docs: https://learn.microsoft.com/en-us/graph/api/channel-list?view=graph-rest-1.0&tabs=http
        $actionMessage = "querying Microsoft Teams Channels"

        do {
            $actionMessage = "querying Microsoft Teams Channels for Team $($microsoftTeam.displayName) ($($microsoftTeam.id))"

            $getMicrosoftTeamsChannelsSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/teams/$($microsoftTeam.id)/Channels?`$select=id,displayName,membershipType,isArchived&`$filter=membershipType eq 'private' OR membershipType eq 'shared'"
                Headers     = $headers
                Method      = "GET"
                Verbose     = $false
                ErrorAction = "Stop"
            }
            if (-not[string]::IsNullOrEmpty($getMicrosoftTeamsChannelsResult.'@odata.nextLink')) {
                $getMicrosoftTeamsChannelsSplatParams["Uri"] = $getMicrosoftTeamsChannelsResult.'@odata.nextLink'
            }

            #Write-Warning ("$($getMicrosoftTeamsChannelsSplatParams.Uri)")
            $getMicrosoftTeamsChannelsResult = $null
            $retryCount = 0
            $maxRetries = 3
            do{
                try{
                    $getMicrosoftTeamsChannelsResult = Invoke-RestMethod @getMicrosoftTeamsChannelsSplatParams
                    $retryCount = 0
                }
                catch {
                    if($_.Exception.Response.StatusCode -eq 429 -or $_.Exception.Response.StatusCode -eq 504){
                        $retryCount++
                        Write-Warning ("retry $retryCount for: $($getMicrosoftTeamsChannelsSplatParams.Uri)")
                        start-sleep -Seconds ($retryCount * 5) 
                        continue
                    }
                    else {
                        throw $_
                    }
                }
            } while ($retryCount -gt 0 -and $retryCount -le $maxRetries)

            if($retryCount -gt $maxRetries){
                throw "Rate limit exceeded."
            }

            # Add Team details to channel objects
            $getMicrosoftTeamsChannelsResult.Value | Add-Member @{ Team = $microsoftTeam }

            if ($getMicrosoftTeamsChannelsResult.Value -is [array]) {
                [void]$microsoftTeamsChannels.AddRange($getMicrosoftTeamsChannelsResult.Value)
            }
            else {
                [void]$microsoftTeamsChannels.Add($getMicrosoftTeamsChannelsResult.Value)
            }
        } while (-not[string]::IsNullOrEmpty($getMicrosoftTeamsChannelsResult.'@odata.nextLink'))
    }
    Write-Information "Queried Microsoft Teams Channels. Result count: $(($microsoftTeamsChannels | Measure-Object).Count)"

    # Send results to HelloID
    $roles = @("Owner", "Member") # supported roles: Owner, Member
    foreach ($role in $roles) {
        $microsoftTeamsChannels | ForEach-Object {
            # Convert membershipType to a more readable format, membershipType can be private, shared or standard, for some reason the API returns 'unknownFutureValue'
            if ($_.membershipType -eq "unknownFutureValue") {
                $memberShipType = "shared"
            }
            else {
                $memberShipType = $_.membershipType
            }
 
            # Shorten DisplayName to max. 100 chars
            $displayName = "Teams Channel - $($_.Team.DisplayName) - $role - $memberShipType - $($_.displayName)"
            $displayName = $displayName.substring(0, [System.Math]::Min(100, $displayName.Length)) 
            
            $outputContext.Permissions.Add(
                @{
                    displayName    = $displayName
                    identification = @{
                        ChannelId = $_.id
                        TeamId    = $_.Team.id
                        Role      = $role
                    }
                }
            )
        }
    }
}
catch {
    Write-Warning ($_ | ConvertTo-Json)
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        Write-Warning "Error at Line '$($errorObj.ScriptLineNumber)': $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        Write-Warning "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
}