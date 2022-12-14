# Manage-RbacRole.ps1

#Requires -Modules powershell-yaml
#Requires -Modules MSAL.PS

# Global variables
$global:prgname         = "Manage-RbacRole"
$global:prgver          = "5"
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
$global:oMap            = @{
	# Hashtable for each ARM and MG object type to help generesize many of the functions
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
function die($msg) {
    Write-Host -ForegroundColor Yellow $msg ; exit
}

function warning($msg) {
    Write-Host -ForegroundColor Yellow $msg
}

function print($msg) {
    Write-Host ($msg)
}

function PrintUsage() {
    die("$prgname Azure RBAC role definition & assignment manager v$prgver`n" +
        "    UUID                              List definition or assignment given its UUID`n" +
        "    -d UUID|SPECFILE|`"role name`"      Delete definition or assignment based on specifier`n" +
        "    -u SPECFILE                       Create or update definition or assignment based on specfile`n" +
        "    -kd[j]                            Create a skeleton role-definition.yaml specfile (JSON option)`n" +
        "    -ka[j]                            Create a skeleton role-assignment.yaml specfile (JSON option)`n" +
        "    -sj                               List all subscription objects in JSON format`n" +
        "`n" +
        "    -z                                Dump variables in running program`n" +
        "    -cr                               Dump values in credentials file`n" +
        "    -cr  TENANT_ID CLIENT_ID SECRET   Set up MSAL automated client_id + secret login`n" +
        "    -cri TENANT_ID USERNAME           Set up MSAL interactive browser popup login`n" +
        "    -tx                               Delete MSAL local session cache`n" +
        "    -v                                Display this usage")
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

function file_size($filePath) {
    return (Get-Item -Path $filePath).Length
}

function remove_file($filePath) {
    Remove-Item $filePath
}

function load_file_yaml($filePath) {
    # Read/load/decode given filePath as some YAML object
    if ( FileExist $filePath ) {
        [string[]]$fileContent = Get-Content $filePath
        $content = ''
        foreach ($line in $fileContent) {
            $content = $content + "`n" + $line
        }
        return ConvertFrom-YAML $content
    }
}

function load_file_json($filePath) {
    return Get-Content $filePath | Out-String | ConvertFrom-Json
}

function save_file_json($jsonObject, $filePath) {
    # Save given JSON object to given filePath
    $jsonObject | ConvertTo-Json -depth 100 | Out-File $filePath  
}

function print_json($jsonObject) {
    print($jsonObject | ConvertTo-Json -Depth 100)
}

function ValidUuid($id) {
    return [guid]::TryParse($id, $([ref][guid]::Empty))
}

function LastElem($s, $splitter) {
    $Split = $s -split $splitter   # Split the string
	return $Split[-1]              # Return last element
}

# =================== LOGIN FUNCTIONS =======================
function dump_variables() {
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

function dump_credentials() {
    # Dump credentials file
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    $creds = load_file_yaml $creds_file
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

function setup_interactive_login($tenant_id, $username) {
    print("Clearing token cache.")
    clear_token_cache
    # Set up credentials file for interactive login
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    if ( -not (ValidUuid $tenant_id) ) {
        die("Error. TENANT_ID is an invalid UUID.")
    }
    $creds_text = "{0,-14} {1}`n{2,-14} {3}`n{4,-14} {5}" -f "tenant_id:", $tenant_id, "username:", $username, "interactive:", "true"
    Set-Content $creds_file $creds_text
    print("$creds_file : Updated credentials")
}

function setup_automated_login($tenant_id, $client_id, $secret) {
    print("Clearing token cache.")
    clear_token_cache
    # Set up credentials file for client_id + secret login
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    if ( -not (valid_uuid $tenant_id) ) {
        die("Error. TENANT_ID is an invalid UUID.")
    }
    if ( -not (valid_uuid $client_id) ) {
        die("Error. CLIENT_ID is an invalid UUID.")
    }
    $creds_text = "{0,-14} {1}`n{2,-14} {3}`n{4,-14} {5}" -f "tenant_id:", $tenant_id, "client_id:", $client_id, "client_secret:", $secret
    Set-Content $creds_file $creds_text
    print("$creds_file : Updated credentials")
}

function setup_credentials() {
    # Read credentials file and set up authentication parameters as global variables
    $creds_file = Join-Path -Path $global:confdir -ChildPath "credentials.yaml"
    if ( (-not (FileExist $creds_file)) -or ((file_size $creds_file) -lt 1) ) {
        die("Missing credentials file: '$creds_file'`n",
            "Please rerun program using '-cr' or '-cri' option to specify credentials.")
    }
    $creds = load_file_yaml $creds_file
    $global:tenant_id = $creds["tenant_id"]
    if ( -not (valid_uuid $global:tenant_id) ) {
        die("[$creds_file] tenant_id '$global:tenant_id' is not a valid UUID")
    }
    if ( $null -eq $creds["interactive"] ) {
        $global:client_id = $creds["client_id"]
        if ( -not (valid_uuid $global:client_id) ) {
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

function setup_api_tokens() {
    # Initialize necessary variables, acquire all API tokens, and set them up to be used GLOBALLY
    setup_credentials  # Sets up tenant ID, client ID, authentication method, etc
    $global:authority_url = "https://login.microsoftonline.com/" + $global:tenant_id

    # This functions allows this utility to call multiple APIs, such as the Azure Resource Management (ARM)
    # and MS Graph, but each one needs its own separate token. The Microsoft identity platform does not allow
    # using ONE token for several APIS resources at once.
    # See https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-net-user-gets-consent-for-multiple-resources

    # ==== Set up MS Graph API token 
    $global:mg_scope = @($global:mg_url + "/.default")  # The scope is a list of strings
    # Appending '/.default' allows using all static and consented permissions of the identity in use
    # See https://learn.microsoft.com/en-us/azure/active-directory/develop/msal-v1-app-scopes
    $global:mg_token = get_token $global:mg_scope     # Note, these are 2 global variable we are updating!
    $global:mg_headers = @{"Authorization" = "Bearer " + $global:mg_token}
    $global:mg_headers.Add("Content-Type", "application/json")

    # ==== Set up ARM AZ API token 
    $global:az_scope = @($global:az_url + "/.default")
    $global:az_token = get_token $global:az_scope
    $global:az_headers = @{"Authorization" = "Bearer " + $global:az_token}
    $global:az_headers.Add("Content-Type", "application/json")

    # You can set up other API tokens here ...
}

function get_token($scopes) {
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

function clear_token_cache() {
    Clear-MsalTokenCache            # Remove cached token from memory
    Clear-MsalTokenCache -FromDisk  # and from disk
}

# =================== API FUNCTIONS =======================
function api_call() {
    param ( [string]$method, $resource, $headers, $data, [switch]$verbose, [switch]$silent )
    if ( $null -eq $headers ) {
        $headers = @{}
    }
    
    # Merge global and additionally called parameters and headers for both AZ and MG APIs
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
            print("==== REQUEST ================================`n" +
                "$method : $resource`n" +
                "PARAMS : $($params | ConvertTo-Json -Depth 100)`n" +
                "HEADERS : $($headers | ConvertTo-Json -Depth 100)`n" +
                "PAYLOAD : $data")
        }
        $ProgressPreference = "SilentlyContinue"  # Don't show progress in the command prompt UI
        switch ( $method.ToUpper() ) {
        "GET"       { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method 'GET' ; break }
        "POST"      { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method 'POST' ; break }
        "DELETE"    { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method 'DELETE' ; break }
        "PATCH"     { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method 'PATCH' ; break }
        }
        if ($verbose) {
            print("==== RESPONSE ================================`n" +
                "STATUS_CODE: $($r.StatusCode)`n" +
                "RESPONSE $($r | ConvertFrom-Json -Depth 100)")
        }
        return ($r | ConvertFrom-Json -Depth 100)
    }
    catch {
        if ( $verbose -or !$silent) {
            print("==== EXCEPTION ================================`n" +
                "MESSAGE: $($_.Exception.Message)`n" +
                "RESPONSE: $($_.Exception.Response | ConvertTo-Json -Depth 100)")
        }
    }
}

function GetObjectName($t, $id) {
	# Return display name for given object
    $x = GetObjectById $t $id
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

function GetObjectById($t, $id) {
	# Retrieve Azure object by UUID
	switch ( $t ) {
        { "a", "d" -eq $_ } {
            # First, search for this object at Tenant root level
            $url = $az_url + "/providers/Microsoft.Management/managementGroups/" + $tenant_id
            $url += "/providers/Microsoft.Authorization/" + $oMap[$t] + "/" + $id + "?api-version=2022-04-01"        
            $r = api_call "GET" ($url) -silent
            if ( $null -ne $r.id ) {
                return $r  # Immediately if found
            }
            # Else, let's search under each Subscription in tenant
            foreach ($subId in get_sub_ids) {
                $url = $az_url + "/subscriptions/" + $subId + "/providers/Microsoft.Authorization/" + $oMap[$t] + "/" + $id
                $r = api_call "GET" ($url + "?api-version=2022-04-01") -silent
                if ( $null -ne $r.id ) {
                    return $r  # Immediately if found
                }
            }
            break  # Needed after each case
        }
        "s" {
            $r = api_call "GET" ($az_url + "/" + $oMap[$t] + "/" + $id + "?api-version=2020-01-01") -silent
            return $r
            break
        }
        "m" {
            $r = api_call "GET" ($az_url + "/providers/Microsoft.Management/managementGroups/" + $id)
            return $r
            break
        }
        { "u", "g", "sp", "ap" -eq $_ } {
            $r = api_call "GET" ($mg_url + "/v1.0/" + $oMap[$t]+ "/" + $id)
            return $r
            break
        }
    }
	return $null
}

function get_sub_ids() {
	# Get all subscription IDs
	# for _, i := range GetAllObjects("s") {   # FUTURE
    $subIds = [System.Collections.Generic.List[string]]::new()
    foreach ($sub in get_subscriptions) {
        if ( $sub.displayName -eq "Access to Azure Active Directory" ) {
            continue
        }
        $subIds.Add($sub.subscriptionId)
    }
	return $subIds
}

function get_subscriptions() {
	$r = api_call "GET" ($az_url + "/" + $oMap["s"] + "?api-version=2020-01-01")
	if ( ($null -ne $r) -and ($null -ne $r.value) ) {
        return $r.value
	}
	return $null
}

# =================== PROGRAM FUNCTIONS =======================
function create_skeleton($fileType) {
    switch ( $fileType.ToLower() ) {
    "-kd"   {
                $name = "role-definition.yaml"
                $content = @"
properties:
  roleName:    My RBAC Role
  description: Description of what this role does.
  assignableScopes:
    # Example scopes of where this role will be DEFINED. Recommendation: Define at highest point only, the Tenant Root Group level.
    # Current limitation: Custom role with dataAction or noDataAction can ONLY be defined at subscriptions level.
    - /providers/Microsoft.Management/managementGroups/3f550b9f-8888-7777-ad61-111199992222
  permissions:
    actions:
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
    ],
    "type": "CustomRole"
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

function show_sp_perms($id) {
    # Show SP MS Graph API permissions
    $r = api_call "GET" ($mg_url + "/v1.0/servicePrincipals/" + $id + "/oauth2PermissionGrants")
    $temp = $r.value | ConvertTo-Json
    if ( $null -eq $temp ) {
        die("Service Principal `"$id`" has no API permissions.")
    }
    foreach ($api in $r.value) {
        $api_name = "Unknown"
        $r2 = api_call "GET" ($mg_url + "/v1.0/servicePrincipals/" + $api.resourceId)
        if ( !$null -eq $r2.appDisplayName) {
            $api_name = $r2.appDisplayName
            $claims = -Split $api.scope.Trim()
            foreach ($i in $claims) {
                print("{0,-50} {1,-50} {2}" -f $api.id, $api_name, $i)
            }
        }
    }
}

function valid_oauth_id($id) {
    # Is this a valid oAuth2PermissionGrant ID?
    $r = api_call "GET" ($mg_url + "/v1.0/oauth2PermissionGrants/" + $id) -silent
    if ( $null -eq $r ) {
        return $false
    }
    return $true
}

function update_perms($id, $claims) {
    if ( valid_oauth_id $id ) {  # Ensure this is legit oAuth2Perms id
        # Update oAuth2Perms
        $payload = @{ "scope" = $claims } | ConvertTo-Json
        $r = api_call "PATCH" ($mg_url + "/v1.0/oauth2PermissionGrants/" + $id) -data $payload
        if ( $null -eq $r ) {
            print_json($r)
        }
    }
}

# --------------------------------------------------------------
function DeleteObject($specifier) {
    # Delete role definition or assignment based on string specifier
    if ( ValidUuid $specifier ) {
        # Delete object with this UUID
        $x = GetObjectById $specifier
        if ( $null -eq $x ) {
            die("There's no object with UUID $specifier.")
        } elseif ( $x.type -eq "Microsoft.Authorization/roleAssignments" ) {
            PrintRoleAssignment($x)
            #Prompt
            #Delete
        } elseif ( $x.type -eq "Microsoft.Authorization/roleDefinitions" ) {
            PrintRoleDefinition($x)
            #Prompt
            #Delete
        } else {

        }
    } elseif ( FileExist $specifier ) {
        # Delete object defined in specfile
    } else {
        # Delete object by this name, if it exists
    }
    exit
}

function PrintRoleDefinition($object) {
	# Print role definition object in YAML-like style format
	if ( $null -eq $object.name ) {
		return
	}

    print("id: {0}" -f $object.name)  # Object UUID
    $x = $object.properties           # Let's use a variable that's simpler to read   
	print("properties:")
	print("  {0} {1}" -f "roleName:", $x.roleName)
	print("  {0} {1}" -f "description:", $x.description)
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

	$permsSet = $x.permissions
    # Observation: PowerShell automatic type coecion converts this array into a single instance if there's only 
    # one element, which is usually the case with these RBAC permission sections. In other words, above should
    # really be $x.permissions[0]. Ran into this PowerShell automatic type coercion pitfall while writing this function
    # https://stackoverflow.com/questions/42355649/array-types-in-powershell-system-object-vs-arrays-with-specific-types

    if ( !$null -eq $permsSet ) {
        print("  {0,-18}" -f "permissions:")
		$permsA = $permsSet.actions
		if ( !$null -eq $permsA ) {
			print("    {0,-16}" -f "actions:")
            foreach ($i in $permsA) {
				print("      - {0}" -f $i)
			}
		}
		$permsDA = $permsSet.dataActions
		if ( !$null -eq $permsDA ) {
			print("    {0,-16}" -f "dataActions:")
            foreach ($i in $permsDA) {
				print("      - {0}" -f $i)
			}
		}
		$permsNA = $permsSet.notActions
		if ( !$null -eq $permsNA ) {
			print("    {0,-16}" -f "notActions:")
            foreach ($i in $permsNA) {
				print("      - {0}" -f $i)
			}
		}
		$permsNDA = $permsSet.notDataActions
		if ( !$null -eq $permsNDA ) {
			print("    {0,-16}" -f "notDataActions:")
            foreach ($i in $permsNDA) {
				print("      - {0}" -f $i)
			}
		}
	} else {
        print("{0,-20} {1}" -f "permissions:", "[]")
	}
}

function PrintRoleAssignment($object) {
	# Print role definition object in YAML-like style format
	if ( $null -eq $object.name ) {
		return
	}

	print("id: {0}" -f $object.name)
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
    print("  {0,-17} {1}  # {3} displayName = {3}" -f "principalId:", $pnId, $pnType, $pnName)

    # If scope is a subscription print its name as a comment at end of line
    if ( $x.scope.StartsWith("/subscriptions") ) {
        $subId = LastElem $x.scope "/"
        $subName = GetObjectName "s" $subId
        print("  {0,-17} {1}  # Sub = {2}" -f "scope:", $x.scope, $subName)
    } else {
        print("  {0,-17} {1}" -f "scope:", $x.scope)
    }
}

function ShowObject($id) {
    # Show any RBAC role definitions and assigment with this UUID
    $x = GetObjectById "a" $id
    if ( $null -ne $x ) {
        $foundDefinition = $True
        PrintRoleAssignment($x)
        exit
    }
    $x = GetObjectById "d" $id
    if ( $null -ne $x ) {
        if ( $foundDefinition ) {
            warning("WARNING! Above definition, as well as below assignment have the same UUID!")
        }
        PrintRoleDefinition($x)
        exit
    }
    exit
}

# =================== MAIN ===========================
if ( ($args.Count -lt 1) -or ($args.Count -gt 4) ) {
    PrintUsage  # Don't accept less than 1 or more than 4 arguments
}

SetupConfDirectory

if ( $args.Count -eq 1 ) {        # Process 1-argument requests
    $arg1 = $args[0]
    # These 1-arg requests don't need for API tokens to be setup
    if ( $arg1 -eq "-cr" ) {
        dump_credentials
    } elseif ( $arg1 -eq "-tx" ) {
        clear_token_cache
        exit
    } elseif ( ($arg1 -eq "-kd") -or ($arg1 -eq "-kdj") -or ($arg1 -eq "-ka") -or ($arg1 -eq "-kaj") ) {
        create_skeleton $arg1
    } elseif ( $arg1 -eq "-v" ) {
        PrintUsage
    }
    # The rest do need API tokens set up
    setup_api_tokens
    if ( ValidUuid $arg1 ) {
        ShowObject $arg1
    } elseif ( $arg1 -eq "-sj" ) {
        $subs = get_subscriptions
        print_json $subs
        exit
    } elseif ( $arg1 -eq "-z" ) {
        dump_variables
    } else {
        PrintUsage
    }
} elseif ( $args.Count -eq 2 ) {  # Process 2-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    setup_api_tokens
    if ( $arg1 -eq "-d" ) {
        DeleteObject $arg2
    } elseif ( ( $arg1 -eq "-a" ) -and ( FileExist $arg2 ) ) {
        create_perms $arg2
    } elseif ( valid_oauth_id $arg1 ) {
        update_perms $arg1 $arg2
    } else {
        PrintUsage
    }
} elseif ( $args.Count -eq 3 ) {  # Process 3-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    if ( $arg1 -eq "-cri" ) {
        setup_interactive_login $arg2 $arg3
    } else {
        PrintUsage
    }
} elseif ( $args.Count -eq 4 ) {  # Process 4-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    $arg4 = $args[3]
    if ( $arg1 -eq "-cr" ) {
        setup_automated_login $arg2 $arg3 $arg4
    } else {
        PrintUsage
    }
} else {
    PrintUsage
}
