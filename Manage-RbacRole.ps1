# Manage-RbacRole.ps1

# Global variables
$global:prgname         = "Manage-RbacRole"
$global:prgver          = "21"
$global:confdir         = ""
$global:tenant_id       = ""
$global:client_id       = ""
$global:client_secret   = ""
$global:interactive     = ""
$global:username        = ""
$global:authority_url   = ""
$global:mg_url          = "https://graph.microsoft.com"
$global:mg_token        = @{}
$global:mg_headers      = @{}
$global:az_url          = "https://management.azure.com"
$global:az_token        = @{}
$global:az_headers      = @{}
$global:oMap            = @{      # Hashtable to help generesize many of the functions
    "d"  = "roleDefinitions"
    "a"  = "roleAssignments"
    "s"  = "subscriptions"
    "m"  = "managementGroups"
    "u"  = "users"
    "g"  = "groups"
    "sp" = "servicePrincipals"
    "ap" = "applications"
}

# =================== HOUSEKEEPING FUNCTIONS =======================
function PrintUsage() {
    die("$prgname Azure RBAC role definition & assignment manager v$prgver`n" +
        "    UUID                              List definition or assignment given its UUID`n" +
        "    -vs SPECFILE                      Compare specfile to what's in Azure`n" +
        "    -rm UUID|SPECFILE|`"role name`"     Delete definition or assignment based on specifier`n" +
        "    -up SPECFILE                      Create or update definition or assignment based on specfile (YAML or JSON)`n" +
        "    -kd[j]                            Create a skeleton role-definition.yaml specfile (JSON option)`n" +
        "    -ka[j]                            Create a skeleton role-assignment.yaml specfile (JSON option)`n" +
        "    -d[j] [SPECIFIER]                 List all role definitions, with SPECIFIER filter and JSON options`n" +
        "    -a[j] [SPECIFIER]                 List all role assignments, with SPECIFIER filter and JSON options`n" +
        "    -s[j] [SPECIFIER]                 List all subscriptions, with SPECIFIER filter and JSON options`n" +
        "`n" +
        "    -z                                Dump variables in running program`n" +
        "    -cr                               Dump values in credentials file`n" +
        "    -cr  TENANT_ID CLIENT_ID SECRET   Set up MSAL automated client_id + secret login`n" +
        "    -cri TENANT_ID USERNAME           Set up MSAL interactive browser popup login`n" +
        "    -tx                               Delete MSAL local session cache`n" +
        "    -v                                Display this usage")
}

function die($msg) {
    Write-Host -ForegroundColor Yellow $msg ; exit
}

function warning($msg) {
    Write-Host -ForegroundColor Yellow $msg
}

function print($msg) {
    Write-Host ($msg)
}

function InstallPsModule($module) {
    try {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Install-Module $module -Scope CurrentUser -Force -AllowClobber
        }
    } catch {
        warning "Unable to isntall required module: $module. $_"
    }
}

function SetupConfDirectory() {
    # Create the utility's config directory
    $homeDir = $null
    if ($IsWindows -or $ENV:OS) {
        $homeDir = $env:USERPROFILE                       # PowerShell in a Windows system
    } else {
        $homeDir = (Get-ChildItem -Path Env:HOME).value   # PowerShell in a non-Windows system
    }
    if ($null -eq $homeDir) {
        die("Fatal. Missing USERPROFILE or HOME environment variable.")
    }
    $global:confdir = Join-Path -Path $homeDir -ChildPath ("." + $prgname)
    if (-not (FileExist $global:confdir)) {
        try {
            New-Item -Path $global:confdir -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
            die("Unable to create directory '$global:confdir'. Error was: $_")
        }
    }
}

function FileExist($filePath) {
    return Test-Path -LiteralPath $filePath
}

function FileSize($filePath) {
    return (Get-Item -Path $filePath).Length
}

function RemoveFile($filePath) {
    Remove-Item $filePath
}

function LoadFileYaml($filePath) {
    # Read/load/decode given filePath as some YAML object
    if ( FileExist $filePath ) {
        [string[]]$fileContent = Get-Content $filePath
        $content = ''
        foreach ($line in $fileContent) {
            $content = $content + "`n" + $line
        }
        try {
            return ConvertFrom-YAML $content
        } catch {
            return $null
        }
    }
}

function LoadFileJson($filePath) {
    try {
        return Get-Content $filePath | Out-String | ConvertFrom-Json
    } catch {
        return $null
    }
}

function SaveFileJson($jsonObject, $filePath) {
    # Save given JSON object to given filePath
    $jsonObject | ConvertTo-Json -depth 100 | Out-File $filePath  
}

function PrintJson($jsonObject) {
    print($jsonObject | ConvertTo-Json -Depth 10)
}

function ValidUuid($id) {
    return [guid]::TryParse($id, $([ref][guid]::Empty))
}

function LastElem($s, $splitter) {
    $Split = $s -split $splitter   # Split the string
	return $Split[-1]              # Return last element
}

# =================== LOGIN FUNCTIONS =======================
function DumpVariables() {
    # Dump essential global variables
    print("{0,-16} {1}" -f "tenant_id:", $global:tenant_id)
    if ( $global:interactive.ToString().ToLower() -eq "true" ) {
        print("{0,-16} {1}" -f "username:", $global:username)
        print("{0,-16} {1}" -f "interactive:", "true")
    } else {
        print("{0,-16} {1}" -f "client_id:", $global:client_id)
        print("{0,-16} {1}" -f "client_secret:", $global:client_secret)
    }
    print("{0,-16} {1}" -f "authority_url:", $global:authority_url)
    if ( Test-Path variable:global:mg_url ) {
        print("{0,-16} {1}" -f "mg_url:", $global:mg_url)
    }
    if ( Test-Path variable:global:az_url ) {
        print("{0,-16} {1}" -f "az_url:", $global:az_url)
    }
    if ( Test-Path variable:global:mg_headers ) {
        print("mg_headers:")
        $global:mg_headers.GetEnumerator() | ForEach-Object {
            print("  {0,-14} {1}" -f $_.Key, $_.Value)
        }
    }
    if ( Test-Path variable:global:az_headers ) {
        print("az_headers:")
        $global:az_headers.GetEnumerator() | ForEach-Object {
            print("  {0,-14} {1}" -f $_.Key, $_.Value)
        }
    }
    exit
}

function DumpCredentials() {
    # Dump credentials file
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    $creds = LoadFileYaml $creds_file
    if ( $null -eq $creds ) {
        die("Error loading $creds_file`n" +
            "Please rerun program using '-cr' or '-cri' option to specify credentials.")
    }
    print("{0,-14} {1}" -f "tenant_id:", $creds["tenant_id"])
    if ( $null -eq $creds["interactive"] ) {
        print("{0,-14} {1}" -f "client_id:", $creds["client_id"])
        print("{0,-14} {1}" -f "client_secret:", $creds["client_secret"])
    } else {
        print("{0,-14} {1}" -f "username:", $creds["username"])
        print("{0,-14} {1}" -f "interactive:", $creds["interactive"])
    }
    exit
}

function SetupInteractiveLogin($tenant_id, $username) {
    print("Clearing token cache.")
    ClearTokenCache
    # Set up credentials file for interactive login
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    if ( -not (ValidUuid $tenant_id) ) {
        die("Error. TENANT_ID is an invalid UUID.")
    }
    $creds_text = "{0,-14} {1}`n{2,-14} {3}`n{4,-14} {5}" -f "tenant_id:", $tenant_id, "username:", $username, "interactive:", "true"
    Set-Content $creds_file $creds_text
    print("$creds_file : Updated credentials")
}

function SetupAutomatedLogin($tenant_id, $client_id, $secret) {
    print("Clearing token cache.")
    ClearTokenCache
    # Set up credentials file for client_id + secret login
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    if ( -not (ValidUuid $tenant_id) ) {
        die("Error. TENANT_ID is an invalid UUID.")
    }
    if ( -not (ValidUuid $client_id) ) {
        die("Error. CLIENT_ID is an invalid UUID.")
    }
    $creds_text = "{0,-14} {1}`n{2,-14} {3}`n{4,-14} {5}" -f "tenant_id:", $tenant_id, "client_id:", $client_id, "client_secret:", $secret
    Set-Content $creds_file $creds_text
    print("$creds_file : Updated credentials")
}

function SetupCredentials() {
    # Read credentials file and set up authentication parameters as global variables
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    if ( (-not (FileExist $creds_file)) -or ((FileSize $creds_file) -lt 1) ) {
        die("Missing credentials file: '$creds_file'`n",
            "Please rerun program using '-cr' or '-cri' option to specify credentials.")
    }
    $creds = LoadFileYaml $creds_file
    $global:tenant_id = $creds["tenant_id"]
    if ( -not (ValidUuid $global:tenant_id) ) {
        die("[$creds_file] tenant_id '$global:tenant_id' is not a valid UUID")
    }
    if ( $null -eq $creds["interactive"] ) {
        $global:client_id = $creds["client_id"]
        if ( -not (ValidUuid $global:client_id) ) {
            die("[$creds_file] client_id '$global:client_id' is not a valid UUID.")
        }
        $global:client_secret = $creds["client_secret"]
        if ( $null -eq $global:client_secret ) {
            die("[$creds_file] client_secret is blank")
        }
    } else {
        $global:username = $creds["username"]
        $global:interactive = $creds["interactive"]
    }
}

function SetupApiTokens() {
    # Initialize necessary variables, acquire all API tokens, and set them up to be used GLOBALLY
    SetupCredentials  # Sets up tenant ID, client ID, authentication method, etc
    $global:authority_url = "https://login.microsoftonline.com/" + $global:tenant_id

    # This functions allows this utility to call multiple APIs, such as the Azure Resource Management (ARM)
    # and MS Graph, but each one needs its own separate token. The Microsoft identity platform does not allow
    # using ONE token for several APIS resources at once.
    # See https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-net-user-gets-consent-for-multiple-resources

    # ==== Set up MS Graph API token 
    $global:mg_scope = @($global:mg_url + "/.default")  # The scope is a list of strings
    # Appending '/.default' allows using all static and consented permissions of the identity in use
    # See https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-v1-app-scopes
    $global:mg_token = GetToken $global:mg_scope     # Note, these are 2 global variable we are updating!
    $global:mg_headers = @{"Authorization" = "Bearer " + $global:mg_token}
    $global:mg_headers.Add("Content-Type", "application/json")

    # ==== Set up ARM AZ API token 
    $global:az_scope = @($global:az_url + "/.default")
    $global:az_token = GetToken $global:az_scope
    $global:az_headers = @{"Authorization" = "Bearer " + $global:az_token}
    $global:az_headers.Add("Content-Type", "application/json")

    # You can set up other API tokens here ...
}

function GetToken($scopes) {
    # See https://github.com/AzureAD/MSAL.PS for more details on these cmdlets
    # Why does this module cache the 'client apps'? It should just be caching accounts + tokens??

    if ( $global:interactive.ToString().ToLower() -eq "true" ) {
        # Interactive login with PublicClientApplication
        # We are using Azure PowerShell client_id for this
        $ps_client_id = "1950a258-227b-4e31-a9cf-717495945fc2"  # Local variable
        # See https://stackoverflow.com/questions/30454771/how-does-azure-powershell-work-with-username-password-based-auth
        # Also https://blog.darrenjrobinson.com/interactive-authentication-to-microsoft-graph-using-msal-with-powershell-and-delegated-permissions/

        # First, let's try getting a client app from the cache
        $app = Get-MsalClientApplication -ClientId $ps_client_id  # GET existing
        if ( $null -eq $app ) {
            # Else, let's get a NEW client app
            $app = New-MsalClientApplication -Authority $global:authority_url -PublicClientOptions @{
                TenantId = $global:tenant_id;
                ClientId = $ps_client_id
            }
            if ( $null -eq $app ) {
                die("Error getting Public client app.")
            }
            # Cache this client app for future sessions
            Enable-MsalTokenCacheOnDisk $app -WarningAction SilentlyContinue
            Add-MsalClientApplication $app
        }
    } else {
        # Client_id + secret login automated login with ConfidentialClientApplication
        # First, let's try getting a client app from the cache
        $app = Get-MsalClientApplication -ClientId $global:client_id  # GET existing
        if ( $null -eq $app ) {
            # Else, let's get a NEW client app
            $app = New-MsalClientApplication -Authority $global:authority_url -ConfidentialClientOptions @{
                TenantId = $global:tenant_id;
                ClientId = $global:client_id;
                ClientSecret = $global:client_secret
            }
            if ( $null -eq $app ) {
                die("Error getting Confidential client app.")
            }
            # Cache this client app for future sessions
            Enable-MsalTokenCacheOnDisk $app -WarningAction SilentlyContinue
            Add-MsalClientApplication $app
        }
    }
    # Getting here means we successfully acquired an app, so now let's get a token
    $token = $app | Get-MsalToken -Scope $scopes
    if ( $null -eq $token ) {
        die("Error getting token.")
    } else {
        return $token.AccessToken   # We only care about the 'secret' string part
    }
    # TO VIEW TOKEN: Install-Module JWTDetails and cat $token | Get-JWTDetails
}

function ClearTokenCache() {
    Clear-MsalTokenCache            # Remove cached token from memory
    Clear-MsalTokenCache -FromDisk  # and from disk
}

# =================== API FUNCTIONS =======================
function ApiCall() {
    param ( [string]$method, $resource, $headers = @{}, $data, [switch]$verbose, [switch]$quiet )
    # Merge global and additionally called headers for both AZ and MG APIs
	if ( $resource.StartsWith($az_url) ) {
        $global:az_headers.GetEnumerator() | ForEach-Object {
            $headers.Add($_.Key, $_.Value)
        }
	} elseif ( $resource.StartsWith($mg_url) ) {
        # MG calls don't seem to use parameters
        $global:mg_headers.GetEnumerator() | ForEach-Object {
            $headers.Add($_.Key, $_.Value)    
        }
	}

    try {
        if ( $verbose ) {
            print("$method : $resource`n" +
                "REQUEST_HEADERS : $($headers | ConvertTo-Json -Depth 10)`n" +
                "REQUEST_PAYLOAD : $data")
        }
        $ProgressPreference = "SilentlyContinue"  # Suppress UI progress indicator
        $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method $method
        $statusCode = $r.StatusCode
        $statusDesc = $r.StatusDescription
        $content = $r.Content
        if ( ($content.GetType() -eq [byte[]]) -and ($content.Count -eq 0) ) {
            # For null body responses, return these 2 status codes
            $result = @{
                "StatusCode" = $statusCode
                "StatusDescription" = $statusDesc
            }
            $r = $result | ConvertTo-Json
        }
        if ($verbose) {
            print("==== RESPONSE ================================`n" +
                "RESPONSE_CODE: $($statusCode)`n" +
                "RESPONSE_DESC: $($statusDesc)`n" +
                "RESPONSE_CONTENT: $($content)")
        }
        return ($r | ConvertFrom-Json)
        # Convert response to native object format for more idiomatic handling
    }
    catch {
        if ( $verbose -or !$quiet) {
            warning("EXCEPTION_MESSAGE: $($_.Exception.Message)")
        }
        if ( $verbose ) {
            print("EXCEPTION_RESPONSE: $($_.Exception.Response | ConvertTo-Json -Depth 10)")
        }
    }
}

function GetObjectName($t, $id) {
	# Return display name for given object
    $x = GetAzObjectById $t $id
    if ( $null -eq $x ) {
        return "null"
    }
    switch ( $t ) {
        "d"     {
            return $x.properties.roleName
        }
        { "s", "u", "g", "sp", "ap" -eq $_ } {
            return $x.displayName
        }
    }
	return "UnkownType"
}

function GetAllAzObjects($t) {
    # Get all Azure objects of type $t
    $oList = @()
    switch ( $t ) {
        { "d", "a" -eq $_ } {
            # Role definitions and assignments
            $uniqueIds = @()
            $url = $az_url + "/providers/Microsoft.Management/managementGroups/" + $global:tenant_id
            $url += "/providers/Microsoft.Authorization/" + $oMap[$t] + "?api-version=2022-04-01"
            $r = ApiCall "GET" ($url) -quiet
            if ( $null -ne $r.value ) {
                $oList = $r.value
                foreach ($i in $r.value) {
                    $uniqueIds += $i.name  # Keep track of each unique object we're adding to the growing list
                }
            }
            # Finally, alse get all the objects under each subscription
            foreach ($subId in GetSubIds) {
                $url = $az_url + "/subscriptions/" + $subId + "/providers/Microsoft.Authorization/" + $oMap[$t] + "?api-version=2022-04-01"
                $r = ApiCall "GET" ($url) -quiet
                if ( $null -ne $r.value ) {
                    foreach ($i in $r.value) {
                        if ( $uniqueIds -Match $i.name) {
                            continue  # Unfortunately objects repeat down the subscription hierarchy, so we avoid them here
                        }
                        $olist += $i
                        $uniqueIds += $i.name
                    }
                }
            }
            return $oList        
        }
        "s" {
            # Subscriptions
            $r = ApiCall "GET" ($az_url + "/" + $oMap["s"] + "?api-version=2020-01-01")
            if ( ($null -ne $r) -and ($null -ne $r.value) ) {
                return $r.value
            }
	        return $null
        }
    }
}

function GetAzObjectById($t, $id) {
	# Retrieve Azure object by UUID
	switch ( $t ) {
        { "a", "d" -eq $_ } {
            # Search for the role definitions at the tenant level
            $url = $az_url + "/providers/Microsoft.Management/managementGroups/" + $global:tenant_id + "/providers/Microsoft.Authorization/" + $oMap[$t] + "?api-version=2022-04-01"
            $r = ApiCall "GET" ($url) -quiet
            if ( $null -ne $r.value ) {
                foreach ($i in $r.value) {
                    if ( $i.name -eq $id ) {  # The 'name' attribute is actually what we're looking for
                        return $i  # Return with object, as soon as we find it
                    }
                }
            }
            # Finally, search for it under each subscription
            foreach ($subId in GetSubIds) {
                $url = $az_url + "/subscriptions/" + $subId + "/providers/Microsoft.Authorization/" + $oMap[$t] + "?api-version=2022-04-01"
                $r = ApiCall "GET" ($url) -quiet
                if ( $null -ne $r.value ) {
                    foreach ($i in $r.value) {
                        if ( $i.name -eq $id ) {
                            return $i  # Again, return as soon as we find it
                        }
                    }
                }
            }
        }
        "s" {
            $r = ApiCall "GET" ($az_url + "/" + $oMap[$t] + "/" + $id + "?api-version=2020-01-01") -quiet
            return $r
        }
        "m" {
            $r = ApiCall "GET" ($az_url + "/providers/Microsoft.Management/managementGroups/" + $id) -quiet
            return $r
        }
        { "u", "g", "sp", "ap" -eq $_ } {
            $r = ApiCall "GET" ($mg_url + "/v1.0/" + $oMap[$t]+ "/" + $id) -quiet
            return $r
        }
    }	
}

function GetAzObjectByName($t, $name) {
	# Retrieve Azure object by displayName
	switch ( $t ) {
        "a" {
            return $null # Role assignments don't have a displayName
        }
        "d" {
            # Search for the role definitions at the tenant level
            $url = $az_url + "/providers/Microsoft.Management/managementGroups/" + $global:tenant_id + "/providers/Microsoft.Authorization/" + $oMap[$t] + "?api-version=2022-04-01"
            $r = ApiCall "GET" ($url) -quiet
            if ( $null -ne $r.value ) {
                foreach ($i in $r.value) {
                    if ( $i.properties.roleName -eq $name ) {
                        return $i  # Return with object, as soon as we find it
                    }
                }
            }
            # Finally, search for it under each subscription
            foreach ($subId in GetSubIds) {
                $url = $az_url + "/subscriptions/" + $subId + "/providers/Microsoft.Authorization/" + $oMap[$t] + "?api-version=2022-04-01"
                $r = ApiCall "GET" ($url) -quiet
                if ( $null -ne $r.value ) {
                    foreach ($i in $r.value) {
                        if ( $i.properties.roleName -eq $name ) {
                            return $i  # Again, return as soon as we find it
                        }
                    }
                }
            }
        }
        "s" {
            $r = ApiCall "GET" ($az_url + "/" + $oMap[$t] + "?api-version=2020-01-01") -quiet
            if ( $null -eq $r) {
                return $
            }
            return $r
        }
        "m" {
            $r = ApiCall "GET" ($az_url + "/providers/Microsoft.Management/managementGroups/" + $id) -quiet
            return $r
        }
        { "u", "g", "sp", "ap" -eq $_ } {
            $r = ApiCall "GET" ($mg_url + "/v1.0/" + $oMap[$t]+ "/" + $id) -quiet
            return $r
        }
    }	
}

function GetSubIds() {
	# Get all subscription UUIDs
    #$subIds = [System.Collections.Generic.List[string]]::new()
    $subIds = @()
    foreach ($sub in GetAllAzObjects "s") {
        if ( $sub.displayName -eq "Access to Azure Active Directory" ) {
            continue
        }
        $subIds += $sub.subscriptionId
    }
	return $subIds
}

function GetAzRoleAssignment($roleDefId, $principalId, $scope) {
    # Get role assignment with given roleId/principalId/scope triad
    $target = LastElem $roleDefId "/"
    $url = $az_url + $scope+ "/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId+eq+'" + $principalId + "'"
    $r = ApiCall "GET" ($url) -quiet
    if ( $null -ne $r.value ) {
        foreach ($i in $r.value) {
            $roleId = LastElem $i.properties.roleDefinitionId "/"
            if ( $roleId -eq $target ) {
                return $i  # We found it
            }
        }
    }
    return $null  # Does not exist
}

function DeleteAzObject($x) {
	# Delete Azure role assignment or definition by its fully qualified ID
    $url = $az_url + $x.id + "?api-version=2022-04-01"       
    $r = ApiCall "DELETE" ($url) -quiet
    if ( $null -eq $r ) {
        die("Error deleting object $($x.id)")
    }
    exit
}

function GetMatching($t, $filter) {
    # Search and retrieve all Azure objects of type $t whose attributes match on $filter 
    $oList = @()
    switch ( $t ) {
        "d" {
            foreach ($i in GetAllAzObjects "d") {
                $p = $i.properties
                # Matching criteria for: Role definitions
                if ( ($i.name -match $filter) -or ($p.roleName -match $filter) -or
                        ($p.type -match $filter) -or ($p.description -match $filter) ) {
                    $oList += $i
                }
            }
            return $oList
        }
        "a" {
            foreach ($i in GetAllAzObjects "a") {
                $p = $i.properties
                # Matching criteria for: Role assignments
                if ( ($i.name -match $filter) -or ($p.principalId -match $filter) -or
                        ($p.roleDefinitionId -match $filter) -or ($p.scope -match $filter) ) {
                    $oList += $i
                }
            }
            return $oList
        }
        "s" {
            foreach ($i in GetAllAzObjects "s") {
                # Matching criteria for: Subscriptions
                if ( ($i.displayName -match $filter) -or ($i.subscriptionId -match $filter) -or
                     ($i.i -match $filter) -or ($p.state -match $filter) ) {
                    $oList += $i
                }
            }
            return $oList
        }
        default {
            return $oList
        }
    }
}

function UpsertAzRoleDefinition($x) {
    # Create or update role definition, as per specfile
    $p = $x.properties
    $name = $p.roleName
    $scope = $p.assignableScopes[0]
    if ( ($null -eq $p ) -or ($null -eq $name ) -or ($null -eq $scope ) -or
         ($null -eq $p.type ) -or ($null -eq $p.description ) ) {
        die("Specfile is missing required attributes.`n" +
            "Run script with '-kd[j]' option to create a properly formatted sample skeleton file.")
    }

    $existing = GetAzObjectByName "d" $name
    if ( $null -eq $existing.name ) {
        print("Creating NEW role definition '{0}' as per specfile" -f $name)
        $roleId = [guid]::NewGuid()  # Generate a new global UUID
    } else {
        print("id: {0}" -f $existing.name)
        PrintAzObject "d" $x  # Print the one we got from specfile
        warning("WARNING: Role already exists in Azure.")
        $Confirm = Read-Host -Prompt "UPDATE existing one with above? y/n "
        if ( $Confirm -ne "y" ) {
            die("Aborted.")
        }
        print("Updating role ...")
        $roleId = $existing.name  # Existing role definition UUID
    }

    # For the scope in the API call we can just use the 1st one
    $body = $x | ConvertTo-Json -Depth 10
    $url = $az_url + $scope + "/providers/Microsoft.Authorization/roleDefinitions/"
    $r = ApiCall "PUT" ( $url + $roleId + "?api-version=2022-04-01") -data $body
    PrintJson $r
    exit    
}

function CreateAzRoleAssignment($x) {
	# Create Azure role assignment
    $p = $x.properties
    $roleDefinitionId = LastElem $p.roleDefinitionId "/"  # Note we only care about the UUID
    $principalId = $p.principalId
    $scope = $p.scope
    if ( ($null -eq $p ) -or ($null -eq $roleDefinitionId ) -or
         ($null -eq $principalId ) -or ($null -eq $scope ) ) {
        die("Specfile is missing one or more of the 3 required attributes.`n`n" +
            "properties:`n" +
            "    roleDefinitionId: <UUID or fully_qualified_role_definition_id>`n" +
            "    principalId: <UUID>`n" +
            "    scope: <resource_path_scope>`n`n" +
            "Run script with '-ka[j]' option to create a properly formatted sample skeleton file.")
    }

    # Note, there is no need to pre-check if assignment exists, since below call will let us know.
    $roleAssignmentName = [guid]::NewGuid()  # Generate a new global UUID
    $payload = @{
        "properties" = @{
            "roleDefinitionId" = "/providers/Microsoft.Authorization/roleDefinitions/" + $roleDefinitionId
            "principalId" = $principalId
        }
    } | ConvertTo-Json
    
    $url = $az_url + $scope + "/providers/Microsoft.Authorization/roleAssignments/"
    $r = ApiCall "PUT" ( $url + $roleAssignmentName + "?api-version=2022-04-01") -data $payload
    PrintJson $r
    exit
}

# =================== PROGRAM FUNCTIONS =======================
function CreateSkeletonFile($fileType) {
    # Create specfile using HereDocs
    switch ( $fileType.ToLower() ) {
    "-kd"   {
                $name = "role-definition.yaml"
                $content = @"
properties:
  roleName:    My RBAC Role
  description: Description of what this role does.
  type: CustomRole
  assignableScopes:
    # Example scopes of where this role will be DEFINED. Recommendation: Define at highest point only, the Tenant Root Group level.
    # Current limitation: Custom role with dataAction or noDataAction can ONLY be defined at subscriptions level.
    - /providers/Microsoft.Management/managementGroups/3f550b9f-8888-7777-ad61-111199992222
  permissions:
    - actions:
        - Microsoft.DevCenter/projects/*/read                     # Sample action
      notActions:
        - Microsoft.DevCenter/projects/pools/read                 # Sample notAction
      dataActions:
        - Microsoft.KeyVault/vaults/secrets/*                     # Sample dataAction
      notDataActions:
        - Microsoft.CognitiveServices/accounts/LUIS/apps/delete   # Sample notDataAction

"@
            ; break
            }
    "-kdj"  {
                $name = "role-definition.json"
                $content = @"
{
  "properties": {
    "roleName": "My RBAC Role",
    "description": "Description of what this role does.",
    "type": "CustomRole",
    "assignableScopes": [
      "/providers/Microsoft.Management/managementGroups/3f550b9f-8888-7777-ad61-111199992222"
    ],
    "permissions": [
      {
        "actions": [
          "Microsoft.DevCenter/projects/*/read"
        ],
        "notActions": [
          "Microsoft.DevCenter/projects/pools/read"
        ],
        "dataActions": [
          "Microsoft.KeyVault/vaults/secrets/*"
        ],
        "notDataActions": [
          "Microsoft.CognitiveServices/accounts/LUIS/apps/delete"
        ]
      }
    ]
  }
}    

"@
                ; break
            }
    "-ka"   {
                $name = "role-assignment.yaml"
                $content = @"
properties:
    roleDefinitionId: 2489dfa4-3333-4444-9999-b04b7a1e4ea6  # Comment to mention the actual roleName = "My Special Role"
    principalId:      65c6427a-1111-5555-7777-274d26531314  # Comment to mention the actual Group displayName = "My Special Group"
    scope:            /providers/Microsoft.Management/managementGroups/3f550b9f-8888-7777-ad61-111199992222

"@
                ; break
            }
    "-kaj"  {
                $name = "role-assignment.json"
                $content = @"
{
  "properties": {
    "roleDefinitionId": "2489dfa4-3333-4444-9999-b04b7a1e4ea6",
    "principalId": "65c6427a-1111-5555-7777-274d26531314",
    "scope": "/providers/Microsoft.Management/managementGroups/3f550b9f-8888-7777-ad61-111199992222"
  }
}

"@
                ; break
            }
    }        
    $skeleton = Join-Path -Path $pwd -ChildPath $name    
    if ( FileExist $skeleton ) {
        die("Error, file `"$skeleton`" already exists.")
    }
    $content | Out-File $skeleton
    exit
}

function DeletePrompt($t, $x) {
    PrintAzObject $t ($x)
    $Confirm = Read-Host -Prompt "DELETE above? y/n "
    if ( $Confirm -eq "y" ) {
        DeleteAzObject $x
        exit
    }
    die("Aborted.")
}

function DeleteObject($specifier) {
    # Delete role definition or assignment based on string specifier
    if ( ValidUuid $specifier ) {
        $x = GetAzObjectById "d" $specifier  # Check definitions
        if ( $null -ne $x ) {
            DeletePrompt "d" $x
        }
        $x = GetAzObjectById "a" $specifier  # Check assignments
        if ( $null -ne $x ) {
            DeletePrompt "a" $x
        }
        die("No assignment or definition with UUID $specifier")
    } elseif ( FileExist $specifier ) {
        # Delete object defined in specfile
        $x = LoadFileYaml $specifier
        if ( $null -eq $x ) {
            $x = LoadFileJson $specifier
            if ( $null -eq $x ) {
                die("$specifier is not a valid YAML or JSON file.")
            }
        }
        if ( $null -ne $x.properties.roleName ) {
            $x = GetAzObjectByName "d" $x.properties.roleName
            DeletePrompt "d" $x
        } elseif ( $null -ne $x.properties.roleDefinitionId ) {
            # Getting assignment objects can't be done by Id or Name, so force to enlist a special function
            $x = GetAzRoleAssignment $x.properties.roleDefinitionId $x.properties.principalId $x.properties.scope
            DeletePrompt "a" $x
        } else {
            die("Files does not appear to be a valid role definition or assignment file.")
        }
    } else {
        # Delete role definition by its displayName, if it exists.
        # This only applies to definitions since assignments do not have a displayName attribute.
        $x = GetAzObjectByName "d" $specifier
        if ( $null -eq $x ) {
            die("There is no role definition with '$specifier' as its name.")
        } else {
            DeletePrompt "d" $x
        }
    }
}

function CompareSpecfile($specfile) {
    if ( -not (FileExist $specfile) ) {
        die("File $specfile does not exist.")
    }
    $ft, $t, $x = GetObjectFromFile $specfile
    if ( ($null -eq $ft) -or ($null -eq $t) -or ($null -eq $x) ) {
        die("Files does not appear to be a valid role definition or assignment specfile.")
    }
    print("`n================ SPECFILE ================")
    PrintAzObject $t $x
    print("`n================ AZURE ===================")
    if ( $t -eq "a" ) {
        $xp = $x.properties
        $r = GetAzRoleAssignment $xp.roleDefinitionId $xp.principalId $xp.scope
        if ($null -eq $r) {
            print("This role assignment does NOT exist in this Azure tenant.")
        } else {
            PrintAzObject "a" $r
        }
    } elseif ( $t -eq "d" ) {
        $r = GetAzObjectByName "d" $x.properties.roleName
        if ($null -eq $r) {
            print("This role definition does NOT exist in this Azure tenant.")
        } else {
            PrintAzObject "d" $r
        }
    } else {
        print("Oh, oh. Unclear what object type this is.")
    }
    print("")
    exit
}

function PrintAzRoleDefinition($object) {
	# Print role definition object in YAML format
	if ( $null -eq $object ) {
		return
	}

    if ( $null -ne $object.name ) {
        print("id: {0}" -f $object.name)
    }
    $x = $object.properties           # Let's use a variable that's simpler to read   
	print("properties:")
	print("  {0} {1}" -f "roleName:", $x.roleName)
	print("  {0} {1}" -f "description:", $x.description)
	print("  {0} {1}" -f "type:", $x.type)
    $scopes = $x.assignableScopes
    if ( !$null -eq $scopes ) {
        print("  {0,-18}" -f "assignableScopes:")
        foreach ($scope in $scopes) {
		    # If scope is a subscription print its name as a comment at end of line
            if ( $scope.StartsWith("/subscriptions") ) {
                $subId = LastElem $scope "/"
                $subName = GetObjectName "s" $subId
                print("    - {0} # {1}" -f $scope, $subName)
            } else {
                print("    - {0}" -f $scope)
            }
        }
	} else {
        print("  {0,-18} {1}" -f "assignableScopes:", "[]")
	}

	$pSet = $x.permissions
    # Observation: PowerShell performs many type conversions behind the scenes, which are typically
    # helpful, but can turn into pitfalls. In this case, the RBAC permission section is actually a
    # a single entry, always. However, PowerShell automatically converts this array into a single
    # instance, and that's unexpected. In other languages above assignment would read $x.permissions[0]

    if ( !$null -eq $pSet ) {
        print("  {0,-18}" -f "permissions:")
        # CRITICAL: Next line is critical, as it ensures this YAML printout represents this
        # permissions section as an array/list, which is what this permission section really is. 
        Write-Host -NoNewline "    - "

		print("{0,-12}" -f "actions:")
		if ( $pSet.actions.Count -gt 0 ) {
            foreach ($i in $pSet.actions) {
				print("        - {0}" -f $i)
			}
		}
        print("      {0,-14}" -f "notActions:")
		if ( $pSet.notActions.Count -gt 0 ) {
            foreach ($i in $pSet.notActions) {
				print("        - {0}" -f $i)
			}
		}
        print("      {0,-14}" -f "dataActions:")
		if ( $pSet.dataActions.Count -gt 0 ) {
            foreach ($i in $pSet.dataActions) {
				print("        - {0}" -f $i)
			}
		}
        print("      {0,-14}" -f "notDataActions:")
		if ( $pSet.notDataActions.Count -gt 0 ) {
            foreach ($i in $pSet.notDataActions) {
				print("        - {0}" -f $i)
			}
		}
	}
}

function PrintAzRoleAssignment($object) {
	# Print role definition object in YAML-like style format
	if ( $null -eq $object ) {
		return
	}

    if ( $null -ne $object.name ) {
        print("id: {0}" -f $object.name)
    }
    $x = $object.properties           # Let's use a variable that's simpler to read 
    print("properties:")
    
    # Print role displayName and principal displayName as comments
	$roleUuid = LastElem $x.roleDefinitionId "/"
    $roleName = GetObjectName "d" $roleUuid
    print("  {0,-17} {1}  # roleName = {2}" -f "roleDefinitionId:", $roleUuid, $roleName)
    $pnId = $x.principalId
    $pnType = $x.principalType
	switch ( $pnType ) {
	    "User"              {  $pnName = GetObjectName "u" $pnId ; break }
	    "ServicePrincipal"  {  $pnName = GetObjectName "sp" $pnId ; break }
	    "Group"             {  $pnName = GetObjectName "g" $pnId ; break }
        default             {  $pnType = "???" ; $pnName = "???" ; break }
    }
    print("  {0,-17} {1}  # {2} displayName = {3}" -f "principalId:", $pnId, $pnType, $pnName)

    # If scope is a subscription print its name as a comment at end of line
    if ( $x.scope.StartsWith("/subscriptions") ) {
        $subId = LastElem $x.scope "/"
        $subName = GetObjectName "s" $subId
        print("  {0,-17} {1}  # Sub = {2}" -f "scope:", $x.scope, $subName)
    } else {
        print("  {0,-17} {1}" -f "scope:", $x.scope)
    }
}

function PrintAzSubscription($object) {
	# Print subscription object in YAML-like style format
	if ( $null -eq $object ) {
		return
	}
    print("{0,-20} {1}" -f "displayName:", $x.displayName)
    print("{0,-20} {1}" -f "subscriptionId:", $x.subscriptionId)
    print("{0,-20} {1}" -f "state:", $x.state)
    print("{0,-20} {1}" -f "tenantId:", $x.tenantId)
}

function PrintAllAzObjectsTersely($t) {
	# List tersely all object of type $t
	foreach ($i in GetAllAzObjects $t ) {  # Iterate through all objects
		PrintAzObjectTersely $t $i
	}
}

function PrintAzObjectTersely($t, $x) {
	# Print this single $t type object tersely (minimal attributes)
	switch ( $t ) {
	    "d" {
            print("{0}  {1,-60}  {2}" -f $x.name, $x.properties.roleName, $x.properties.type)
        }
	    "a" {
            $p = $x.properties
            $roleId = LastElem $p.roleDefinitionId "/"
            print("{0}  {1}  {2} {3,-18} {4}"-f $x.name, $roleId, $p.principalId, $p.principalType, $p.scope)
        }
	    "s" {
            print("{0}  {1,-10}  {2}"-f $x.subscriptionId, $x.state, $x.displayName)
        }
	}
}

function PrintAzObject($t, $x) {
    # Generisized print_object function
	switch ( $t ) {
	    "d" {
		    PrintAzRoleDefinition $x
        }
	    "a" {
		    PrintAzRoleAssignment $x
        }
	    "s" {
		    PrintAzSubscription $x
        }
    }
}

function ShowObject($id) {
    # Show any RBAC role definitions and assigment with this UUID
    $x = GetAzObjectById "d" $id
    if ( $null -ne $x ) {
        PrintAzRoleDefinition($x)
        $foundDefinition = $True
    }
    $x = GetAzObjectById "a" $id
    if ( $null -ne $x ) {
        if ( $foundDefinition ) {
            # Hopefully this is never seen
            warning("WARNING! Above role definition, and below role assignment both have the same UUID!")
        }
        PrintAzRoleAssignment($x)
    }
    exit
}

function GetObjectFromFile($specfile) {
    # Returns an array of 3 values: [0] = File format type, [1] = Object type, and [2] = Object itself
    
    # Let's pretend it's a YAML file
    $x = LoadFileYaml $specfile
    $ft = "YAML"
    if ( $null -eq $x ) {
        # That didn't work, so let's try JSON
        $x = LoadFileJson $specfile
        $ft = "JSON"
        if ( $null -eq $x ) {
            $x = $null
            $ft = $null
        }
    }

    # We seem to have a would-be object from the file
    if ( $null -ne $x.properties.roleName ) {
        # It's a role definition 
        return $ft, "d", $x   # Type can then neatly be used with other generized $oMap functions
    } elseif ( $null -ne $x.properties.roleDefinitionId ) {
        # It's a role assignment 
        return $ft, "a", $x
    } else {
        return $null, $null, $null
    }
}

function UpsertAzObject($specfile) {
    # Create or Update role definition or assignment
    if ( -not (FileExist $specfile) ) {
        die("File $specfile does not exist.")
    }

    $ft, $t, $x = GetObjectFromFile $specfile     # $ft is now used here
    if ( ($null -ne $t) -and ($t -eq "d") ) {
        UpsertAzRoleDefinition $x
    } elseif ( ($null -ne $t) -and ($t -eq "a") ) {
        CreateAzRoleAssignment $x
    } else {
        die("File does not appear to be a valid role definition or assignment specfile.")
    }
}

# =================== MAIN ===========================
if ( ($args.Count -lt 1) -or ($args.Count -gt 4) ) {
    PrintUsage  # Don't accept less than 1 or more than 4 arguments
}

InstallPsModule "powershell-yaml"
InstallPsModule "MSAL.PS"

SetupConfDirectory

if ( $args.Count -eq 1 ) {        # Process 1-argument requests
    $arg1 = $args[0]
    # These 1-arg requests don't need credentials and API tokens to be setup
    if ( $arg1 -eq "-cr" ) {
        DumpCredentials
    } elseif ( $arg1 -eq "-tx" ) {
        ClearTokenCache
        exit
    } elseif ( ($arg1 -eq "-kd") -or ($arg1 -eq "-kdj") -or ($arg1 -eq "-ka") -or ($arg1 -eq "-kaj") ) {
        CreateSkeletonFile $arg1
    } elseif ( $arg1 -eq "-v" ) {
        PrintUsage
    }
    # The rest do need global credentials and API tokens available
    SetupApiTokens
    if ( ValidUuid $arg1 ) {
        ShowObject $arg1
    } elseif ( ($arg1 -eq "-dj") -or ($arg1 -eq "-aj") -or ($arg1 -eq "-sj") ) {
        $t = $arg1.Substring(1,1)    # Get object type designator
        $allObjects = GetAllAzObjects $t
        PrintJson ($allObjects)
        exit
    } elseif ( ($arg1 -eq "-d") -or ($arg1 -eq "-a") -or ($arg1 -eq "-s") ) {
        $t = $arg1.Substring(1,1)    # Get object type designator
        PrintAllAzObjectsTersely $t
        exit
    } elseif ( $arg1 -eq "-z" ) {
        DumpVariables
    } else {
        PrintUsage
    }
} elseif ( $args.Count -eq 2 ) {  # Process 2-argument requests
    $arg1 = $args[0] ; $arg2 = $args[1]
    SetupApiTokens
    if ( $arg1 -eq "-vs" ) {
        CompareSpecfile $arg2
    } elseif ( $arg1 -eq "-rm" ) {
        DeleteObject $arg2
    } elseif ( $arg1 -eq "-up" ) {
        UpsertAzObject $arg2  # Create or Update role definition or assignment
    } elseif ( ($arg1 -eq "-dj") -or ($arg1 -eq "-aj") -or ($arg1 -eq "-sj") ) {
        # Process request with JSON formatted output option
        $t = $arg1.Substring(1,1)    # Get object type designator
        $objects = GetMatching $t $arg2   # Get all matching objects
        if ( $objects.Count -gt 1 ) {
            PrintJson $objects
        } elseif ( $objects.Count -gt 0 ) {
            PrintJson $objects[0]
        }
        exit
    } elseif ( ($arg1 -eq "-d") -or ($arg1 -eq "-a") -or ($arg1 -eq "-s") ) {
        # Process request with reguarly, tersely formatted output option
        $t = $arg1.Substring(1,1)    # Get object type designator
        $objects = GetMatching $t $arg2
        if ( $objects.Count -gt 1 ) {
            foreach ($i in $objects) {
                PrintAzObjectTersely $t $i
            }
        } elseif ( $objects.Count -gt 0 ) {
            PrintAzObject $t $objects[0]
        }
        exit
    } else {
        PrintUsage
    }
} elseif ( $args.Count -eq 3 ) {  # Process 3-argument requests
    $arg1 = $args[0] ; $arg2 = $args[1] ; $arg3 = $args[2]
    if ( $arg1 -eq "-cri" ) {
        SetupInteractiveLogin $arg2 $arg3
    } else {
        PrintUsage
    }
} elseif ( $args.Count -eq 4 ) {  # Process 4-argument requests
    $arg1 = $args[0] ; $arg2 = $args[1] ; $arg3 = $args[2] ; $arg4 = $args[3]
    if ( $arg1 -eq "-cr" ) {
        SetupAutomatedLogin $arg2 $arg3 $arg4
    } else {
        PrintUsage
    }
} else {
    PrintUsage
}
