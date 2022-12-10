# Manage-SP-Auth.ps1

#Requires -Modules powershell-yaml
#Requires -Modules MSAL.PS

# Global variables
$global:prgname         = "Manage-SpAuth"
$global:prgver          = "25"
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

# =================== HOUSEKEEPING FUNCTIONS =======================
function die($msg) {
    Write-Host -ForegroundColor Yellow $msg ; exit
}

function print($msg) {
    Write-Host ($msg)
}

function print_usage() {
    die("$prgname Azure SP API permissions utility v$prgver`n" +
        "    SP_OBJECT_UUID                        Display Service Principal API permissions`n" +
        "    -a oAuth2PermissionGrant_object.json  Create oAuth2PermissionGrant based on file`n" +
        "    -k                                    Create a skeleton oAuth2PermissionGrant_object.json file`n" +
        "    ID                                    Display oAuth2PermissionGrants object`n" +
        "    -d ID                                 Delete oAuth2PermissionGrants ID`n" +
        "    ID `"space-separated claims list`"      Update oAuth2PermissionGrants ID with provided claims list`n" +
        "`n" +
        "    -z                                    Dump variables in running program`n" +
        "    -cr                                   Dump values in credentials file`n" +
        "    -cr  TENANT_ID CLIENT_ID SECRET       Set up MSAL automated client_id + secret login`n" +
        "    -cri TENANT_ID USERNAME               Set up MSAL interactive browser popup login`n" +
        "    -tx                                   Delete MSAL local session cache")
}

function setup_confdir() {
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
    if (-not (file_exist $global:confdir)) {
        try {
            New-Item -Path $global:confdir -ItemType Directory -ErrorAction Stop | Out-Null #-Force
        }
        catch {
            die("Unable to create directory '$global:confdir'. Error was: $_")
        }
    }
}

function file_exist($filePath) {
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
    if ( file_exist $filePath ) {
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
    print($jsonObject | ConvertTo-Json)
}

function valid_uuid($id) {
    return [guid]::TryParse($id, $([ref][guid]::Empty))
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
    if ( -not (valid_uuid $tenant_id) ) {
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
    if ( (-not (file_exist $creds_file)) -or ((file_size $creds_file) -lt 1) ) {
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
    # Initialize necessary global variables, acquire all API tokens, and set them up for use
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
    param ( [string]$method, $resource, $headers, $params, $data, [switch]$verbose, [switch]$silent )
    if ( $null -eq $headers ) {
        $headers = @{}
    }
    $global:mg_headers.GetEnumerator() | ForEach-Object {
        $headers.Add($_.Key, $_.Value)    # Append global headers
    }
    try {
        if ( $verbose ) {
            print("==== REQUEST ================================`n" +
                "$method : $resource`n" +
                "PARAMS : $($params | ConvertTo-Json -Depth 100)`n" +
                "HEADERS : $($headers | ConvertTo-Json -Depth 100)`n" +
                "PAYLOAD : $data")
        }
        switch ( $method.ToUpper() ) {
            "GET"       { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Method 'GET' ; break }
            "POST"      { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method 'POST' ; break }
            "DELETE"    { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method 'DELETE' ; break }
            "PATCH"     { $r = Invoke-WebRequest -Headers $headers -Uri $resource -Body $data -Method 'PATCH' ; break }
        }
        if ($verbose) {
            print("==== RESPONSE ================================`n" +
                "STATUS_CODE: $($r.StatusCode)`n" +
                "RESPONSE $($r | ConvertFrom-Json -Depth 100)")
        }
        return ($r | ConvertFrom-Json)
    }
    catch {
        if ( $verbose -or !$silent) {
            print("==== EXCEPTION ================================`n" +
                "MESSAGE: $($_.Exception.Message)`n" +
                "RESPONSE: $($_.Exception.Response | ConvertTo-Json -Depth 100)")
        }
    }
}

# =================== PROGRAM FUNCTIONS =======================
function create_skeleton() {
    $skeleton = Join-Path -Path $pwd -ChildPath "oAuth2PermissionGrant_object.json"
    if ( file_exist $skeleton ) {
        die("Error. File `"$skeleton`" already exists.")
    }
    $content = @{
        "clientId"    = "CLIENT_SP_UUID"
        "consentType" = "AllPrincipals"
        "resourceId"  = "API_SP_UUID"
        "scope"       = "space-separated claims list like openid profile"
    }
    save_file_json $content $skeleton
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

function show_perms($id) {
    # Show oAuth2PermissionGrant permissions
    $r = api_call "GET" ($mg_url + "/v1.0/oauth2PermissionGrants/" + $id)
    if ( $null -eq $r.error ) {
        print_json($r)
    } else {
        die($r)
    }
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

function delete_perms($id) {
    # Delete oAuth2Perms
    $r = api_call "DELETE" ($mg_url + "/v1.0/oauth2PermissionGrants/" + $id)
    if ( $null -eq $r ) {
        print_json($r)
    }
}

function create_perms($filePath) {
    # Create oAuth2Perms
    $payload = load_file_json $filePath | ConvertTo-Json
    $r = api_call "POST" ($mg_url + "/v1.0/oauth2PermissionGrants") -data $payload
    if ( $null -eq $r ) {
        print_json($r)
    }
}

# =================== MAIN ===========================
if ( ($args.Count -lt 1) -or ($args.Count -gt 4) ) {
    print_usage  # Don't accept less than 1 or more than 4 arguments
}

setup_confdir

if ( $args.Count -eq 1 ) {        # Process 1-argument requests
    $arg1 = $args[0]
    # These 1-arg requests don't need for API tokens to be setup
    if ( $arg1 -eq "-cr" ) {
        dump_credentials
    } elseif ( $arg1 -eq "-tx" ) {
        clear_token_cache
        exit
    } elseif ( $arg1 -eq "-k" ) {
        create_skeleton
    }
    # The rest do need API tokens set up
    setup_api_tokens
    if ( valid_uuid $arg1 ) {
        show_sp_perms $arg1 
    } elseif ( $arg1 -eq "-z" ) {
        dump_variables
    } elseif ( valid_oauth_id $arg1 ) {
        show_perms $arg1
    } else {
        print_usage
    }
} elseif ( $args.Count -eq 2 ) {  # Process 2-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    setup_api_tokens
    if ( $arg1 -eq "-d" ) {
        delete_perms $arg2
    } elseif ( ( $arg1 -eq "-a" ) -and ( file_exist $arg2 ) ) {
        create_perms $arg2
    } elseif ( valid_oauth_id $arg1 ) {
        update_perms $arg1 $arg2
    } else {
        print_usage
    }
} elseif ( $args.Count -eq 3 ) {  # Process 3-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    if ( $arg1 -eq "-cri" ) {
        setup_interactive_login $arg2 $arg3
    } else {
        print_usage
    }
} elseif ( $args.Count -eq 4 ) {  # Process 4-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    $arg4 = $args[3]
    if ( $arg1 -eq "-cr" ) {
        setup_automated_login $arg2 $arg3 $arg4
    } else {
        print_usage
    }
} else {
    print_usage
}
