####################################################################
# HelloID-Conn-Prov-Target-Microsoft-Entra-ID-EducationalGroups-Members-ImportSubPermissions
# PowerShell V2
####################################################################

# Enable TLS1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# Configure, must be the same as the values used in retrieve permissions
$permissionReference = 'EDU-Teams-Members'
$permissionDisplayName = 'EDU Teams - Members'

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

function Invoke-MSEntraBatchRequest {
    <#
        Executes GET requests for a list of items against the Microsoft Graph $batch endpoint
        (https://learn.microsoft.com/en-us/graph/json-batching), instead of one request per item.
        Returns a hashtable keyed by the (0-based) index of $Items, where each value is the
        (paginated, fully resolved) 'value' array of that item's response.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]
        $Items,

        [Parameter(Mandatory)]
        [hashtable]
        $Headers,

        [Parameter(Mandatory)]
        [scriptblock]
        $UriScriptBlock,

        [int]
        $BatchSize = 20
    )
    process {
        $resultsByIndex = @{}

        for ($i = 0; $i -lt $Items.Count; $i += $BatchSize) {
            $batchItems = $Items[$i..[Math]::Min($i + $BatchSize - 1, $Items.Count - 1)]

            $batchRequests = [System.Collections.Generic.List[object]]::new()
            for ($j = 0; $j -lt $batchItems.Count; $j++) {
                [void]$batchRequests.Add(
                    @{
                        id     = "$j"
                        method = 'GET'
                        url    = (& $UriScriptBlock $batchItems[$j])
                    }
                )
            }

            $batchSplatParams = @{
                Uri         = 'https://graph.microsoft.com/v1.0/$batch'
                Headers     = $Headers
                Method      = 'POST'
                Body        = (@{ requests = $batchRequests } | ConvertTo-Json -Depth 10)
                ContentType = 'application/json; charset=utf-8'
                Verbose     = $false
                ErrorAction = 'Stop'
            }

            $batchResponse = $null
            $retryCount = 0
            $maxRetries = 3
            do {
                try {
                    $batchResponse = Invoke-RestMethod @batchSplatParams
                    $retryCount = 0
                }
                catch {
                    if ($_.Exception.Response.StatusCode -eq 429 -or $_.Exception.Response.StatusCode -eq 504) {
                        $retryCount++
                        Write-Warning "Retry [$retryCount] for batch request covering items [$i..$($i + $batchItems.Count - 1)]"
                        Start-Sleep -Seconds ($retryCount * 5)
                        continue
                    }
                    else {
                        throw
                    }
                }
            } while ($retryCount -gt 0 -and $retryCount -le $maxRetries)

            if ($retryCount -gt $maxRetries) {
                throw "Rate limit exceeded for batch request covering items [$i..$($i + $batchItems.Count - 1)]."
            }

            foreach ($response in $batchResponse.responses) {
                $itemIndex = $i + [int]$response.id
                if ($response.status -ge 200 -and $response.status -lt 300) {
                    $values = [System.Collections.ArrayList]@()
                    if ($null -ne $response.body.value) {
                        [void]$values.AddRange(@($response.body.value))
                    }
                    $nextLink = $response.body.'@odata.nextLink'
                    while (-not [string]::IsNullOrEmpty($nextLink)) {
                        $paginationSplatParams = @{
                            Uri         = $nextLink
                            Headers     = $Headers
                            Method      = 'GET'
                            ContentType = 'application/json; charset=utf-8'
                            Verbose     = $false
                            ErrorAction = 'Stop'
                        }
                        $paginationResponse = Invoke-RestMethod @paginationSplatParams
                        [void]$values.AddRange(@($paginationResponse.value))
                        $nextLink = $paginationResponse.'@odata.nextLink'
                    }
                    $resultsByIndex[$itemIndex] = $values
                }
                else {
                    Write-Warning "Batch sub-request failed for item at index [$itemIndex]: $($response.body.error.message)"
                    $resultsByIndex[$itemIndex] = @()
                }
            }
        }

        Write-Output $resultsByIndex
    }
}

function Get-SchoolYear {
    # Calculate school year dependencies
    # School year definition in numbers of 4 or 2 digits
    $schoolYearLength = 2 # Length of school year used in the Teams name - e.g. 24-25 for 2 or 2024-2025 for 4
    $schoolYearSeperator = "" # Used in the Teams name - can be empty
    
    if ($schoolYearLength -eq 2) { $format = "yy" } else { $format = "yyyy" }
    
    $monthcurrent = (Get-Date).Month
    $yearcurrent = (Get-Date).ToString($format)
    $yearprevious = ([int]$yearcurrent - 1).ToString()
    $yearnext = ([int]$yearcurrent + 1).ToString()
    
    If ($monthcurrent -ge 8) {
        $schoolyear = $yearcurrent + $schoolYearSeperator + $yearnext
    }
    else {
        $schoolyear = $yearprevious + $schoolYearSeperator + $yearcurrent
    }
    return $schoolyear
}
#endregion functions


try {
    # Make sure the search query returns the same scope as the 'Handle all action script'. If this is not possible with GraphApi, then filter the data after retrieving it.
    # Example using department_<departmentName>=
    # $searchQuery = "`$filter=startswith(displayName,'department')"
    # Example when using function_<functionName>_department_<departmentName>:
    $schoolyear = Get-SchoolYear
    $searchQuery = '$search="displayName:' + $schoolyear + '"'

    # Setup Connection with Entra/Exo
    $actionMessage = 'connecting to MS-Entra'
    $certificate = Get-MSEntraCertificate
    $entraToken = Get-MSEntraAccessToken -Certificate $certificate

    $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
    $headers.Add('Authorization', "Bearer $entraToken")
    $headers.Add('Accept', 'application/json')
    $headers.Add('Content-Type', 'application/json')
    # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
    $headers.Add('ConsistencyLevel', 'eventual')

    # # API docs: https://learn.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
    $actionMessage = "querying groups"
    $entraIDGroups = @()
    $uri = "https://graph.microsoft.com/v1.0/groups?$searchQuery"
    do {
        $getGroupsSplatParams = @{
            Uri         = $uri
            Headers     = $headers
            Method      = 'GET'
            ContentType = 'application/json; charset=utf-8'
            Verbose     = $false
            ErrorAction = "Stop"
        }
        $response = Invoke-RestMethod @getGroupsSplatParams
        $entraIDGroups += $response.value
        Write-Information "Successfully queried [$($entraIDGroups.count)] existing groups"
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    # Using the Batch API to retrieve group members for all groups in batches of 20 (https://learn.microsoft.com/en-us/graph/json-batching)
    $actionMessage = "querying group members"
    $entraIDGroupsMembers = Invoke-MSEntraBatchRequest -Items $entraIDGroups -Headers $headers -UriScriptBlock {
        param($group)
        "/groups/$($group.id)/members?`$select=id&`$top=999"
    }

    for ($groupIndex = 0; $groupIndex -lt $entraIDGroups.Count; $groupIndex++) {
        $entraIDGroup = $entraIDGroups[$groupIndex]
        $entraIDGroupMembers = @($entraIDGroupsMembers[$groupIndex] | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.user" -and $_.id -ne $actionContext.Configuration.ownerGuid })
        $numberOfAccounts = $(($entraIDGroupMembers | Measure-Object).Count)

        # Make sure the displayName has a value of max 100 char
        if (-not([string]::IsNullOrEmpty($entraIDGroup.displayName))) {
            $displayName = $($entraIDGroup.displayName).substring(0, [System.Math]::Min(100, $($entraIDGroup.displayName).Length))
        }
        else {
            $displayName = $entraIDGroup.id
        }

        $permission = @{
            PermissionReference      = @{
                Reference = $permissionReference
            }       
            DisplayName              = "$permissionDisplayName"
            Description              = "$permissionDisplayName"
            SubPermissionReference   = @{
                Id = $entraIDGroup.id
            }
            SubPermissionDisplayName = $displayName
        }

        # Batch permissions based on the amount of account references, 
        # to make sure the output objects are not above the limit
        $accountsBatchSize = 500
        if ($numberOfAccounts -gt 0) {
            $accountsBatchSize = 500
            $batches = 0..($numberOfAccounts - 1) | Group-Object { [math]::Floor($_ / $accountsBatchSize ) }
            foreach ($batch in $batches) {
                $permission.AccountReferences = [array]($batch.Group | ForEach-Object { @($entraIDGroupMembers[$_].id) })
                Write-Output $permission
            }
        }
    }
}
catch {
    $ex = $PSItem
    if ($($ex.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or
        $($ex.Exception.GetType().FullName -eq 'System.Net.WebException')) {
        $errorObj = Resolve-MS-Entra-ExoError -ErrorObject $ex
        $auditMessage = "Error $($actionMessage). Error: $($errorObj.FriendlyMessage)"
        $warningMessage = "Error at Line [$($errorObj.ScriptLineNumber)]: $($errorObj.Line). Error: $($errorObj.ErrorDetails)"
    }
    else {
        $auditMessage = "Error $($actionMessage). Error: $($ex.Exception.Message)"
        $warningMessage = "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($ex.Exception.Message)"
    }
    Write-Warning $warningMessage
    Write-Error $auditMessage
}