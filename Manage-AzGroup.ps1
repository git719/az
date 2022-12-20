# Manage-AzGroup.ps1

#Requires -Modules powershell-yaml
#Requires -Modules MSAL.PS

# Global variables
$global:prgname         = "Manage-AzGroup"
$global:prgver          = "17"
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
$global:oMap            = @{      # Hashtable to help generesize many of the functions
    "u"  = "users"
    "g"  = "groups"
    "sp" = "servicePrincipals"
    "ap" = "applications"
}

# =================== HOUSEKEEPING FUNCTIONS =======================
function PrintUsage() {
    die("$prgname AZ group management utility v$prgver`n" +
        "    -vs NAME|UUID                     Display existing AZ group with given displayName or UUID`n" +
        "    -rm NAME|UUID                     Delete existing AZ group with given displayName or UUID`n" +
        "    -up NAME [DESC] [OWNER] [ASSIGN]  Create AZ group with given displayName (mandatory) and other optional params`n`n" +
        "        Note, DESC can be in quotes, OWNER must be in quotes also and comma-separated if multiple,`n" +
        "        and ASSIGN sets the 'isAssignableToRole' attribute to 'false' by default. If setting ASSIGN to`n" +
        "        'true', then you *must* also include DESC and OWNER (at least as null `"`"). Examples:`n`n" +
        "          $prgname -up my_group1`n" +
        "          $prgname -up my_group2 `"my desc`"`n" +
        "          $prgname -up my_group3 `"my desc`" `"owner1@domain.com`"`n" +
        "          $prgname -up my_group4 `"`" `"`" true`n" +
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
    if ( Test-Path variable:global:az_url ) {
        # If az_url not setup globally, then not needed/used by this util
        $global:az_scope = @($global:az_url + "/.default")
        $global:az_token = GetToken $global:az_scope
        $global:az_headers = @{"Authorization" = "Bearer " + $global:az_token}
        $global:az_headers.Add("Content-Type", "application/json")
    }
    # You can set up other API tokens belo ...
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
	if ( (Test-Path variable:global:az_url) -and $resource.StartsWith($az_url) ) {
        $global:az_headers.GetEnumerator() | ForEach-Object {
            $headers.Add($_.Key, $_.Value)
        }
	} elseif ( (Test-Path variable:global:mg_url) -and $resource.StartsWith($mg_url) ) {
        # MG calls don't seem to use parameters
        $global:mg_headers.GetEnumerator() | ForEach-Object {
            $headers.Add($_.Key, $_.Value)    
        }
	} # Future: Setup other optional API url header updates here

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

function MgObjectExists($t, $displayName) {
    # Check if object of type $t with this displayName exists
    $headers = @{ "ConsistencyLevel" = "eventual" }
    $r = ApiCall "GET" ($mg_url + "/v1.0/" + $oMap[$t] + "?`$search=`"displayName:" + $displayName + "`"&`$count=true") -headers $headers -quiet
    if ( $r.'@odata.count' -gt 0 ) {
        foreach ($x in $r.value) {
            if ( $x.displayName.ToLower() -eq $displayName.ToLower() ) {  # Must be exact legth match
                return $true
            }
        }
    }
}

function GetMgObject($t, $specifier) {
    # Get existing object of type $t
    if ( ValidUuid $specifier ) {
        $headers = @{}
        $url = "/v1.0/" + $oMap[$t] + "/" + $specifier
    } else {
        $headers = @{ "ConsistencyLevel" = "eventual" }
        $url = "/v1.0/" + $oMap[$t] + "?`$search=`"displayName:" + $specifier + "`"&`$count=true"
    }
    $r = ApiCall "GET" ($mg_url + $url) -headers $headers -quiet
    if ( ($null -ne $r) -or ($r.'@odata.count' -gt 0) ) {
        return $r
    }
    return $null
}

function DeleteMgObject($t, $x) {
    # Delete MS Graph object type $t
    $url = $mg_url + "/v1.0/" + $oMap[$t] + "/" + $x.id
    $r = ApiCall "DELETE" ($url) -quiet
    if ( ($null -ne $r) -and ($r.StatusCode -ne 204) ) {
        die("Error deleting object $($x.id)")
    }
}

# =================== PROGRAM FUNCTIONS =======================
function DisplayGroup($specifier) {
    $x = GetMgObject "g" $specifier
    if ( ( ($null -ne $x.'@odata.count') -and ($x.'@odata.count' -gt 1) ) ) {
        print("All these groups, share that same displayName")
        foreach ( $g in $x.value ) {
            print("{0}  {1}" -f $g.id, $g.displayName)
        }
    } elseif ( ($null -ne $x.id) ) { 
        print("{0}  {1}" -f $x.id, $x.displayName)
    } elseif ( ($x.'@odata.count' -eq 1) -and ($x.value[0].displayName -eq $specifier) ) { 
        print("{0}  {1}" -f $x.value[0].id, $x.value[0].displayName)
    } else {
        print("Group does NOT exist")
    }
    exit    
}

function DeleteGroup($specifier) {
    $x = GetMgObject "g" $specifier
    if ( ($null -eq $x) -or ( ($null -ne $x.'@odata.count') -and ($x.'@odata.count' -eq 0) ) ) {
        die("There's no group with specifier = $specifier")
    }
    if ( $x.'@odata.count' -gt 1 ) {
        die("There are many groups with that same displayName. Please delete by UUID.")
    }
    if ( $null -ne $x.value ) {
        $x = $x.value[0]  # Single out the only finding
    }
    print("`nDisplayName  = $($x.displayName)")
    print("ObjectId     = $($x.id)")
    print("Description  = $($x.description)`n")
    $confirm = Read-Host -Prompt "DELETE above? y/n"
    if ( $confirm -eq "y" ) {
        DeleteMgObject "g" $x
    }
    exit
}

function CreateAzGroup($displayName, $description = "", $owner = "", $assignable = $False) {
    if ( MgObjectExists "g" $displayName ) {
        die("A group named `"$displayName`" already exists.")
    }
    if ( $description -eq "" ) {
        $description = $displayName
    }
    if ( $owner -eq "" ) {
        # Not working yet
        $owner = "Empty"
    }
    if ( ($null -eq $assignable) -or (!$assignable) ) {
        $assignable = $False
    }
    $payload = @{
        "displayName"        = $displayName
        "mailEnabled"        = $False
        "mailNickname"       = "NotSet"
        "securityEnabled"    = $True
        # Above 4 are REQUIRED, others are optional
        "description"        = $description
        "isAssignableToRole" = $assignable
    } | ConvertTo-Json

    # Add owner option here

    # BUG # Why is below call failing with HTTP 400 Bad Request?
    $r = ApiCall "POST" ($mg_url + "/v1.0/groups") -data $payload
    if ( ($null -eq $r) -or ($null -eq $r.id) ) {
        die("Error creating group.")
    }

    print("Group Name   = " + $r.displayName)
    print("Object Id    = " + $r.id)
    print("Description  = " + $r.description)
    print("Owner        = " + $owner)
    print("Assignable   = " + $r.isAssignableToRole)
    exit
}

# =================== MAIN ===========================
if ( ($args.Count -lt 1) -or ($args.Count -gt 5) ) {
    PrintUsage  # Don't accept less than 1 or more than 5 arguments
}

SetupConfDirectory

if ( $args.Count -eq 1 ) {          # Process 1-argument requests
    $arg1 = $args[0]
    # These first 1-arg requests don't need for API tokens to be setup
    if ( $arg1 -eq "-cr" ) {
        DumpCredentials
    } elseif ( $arg1 -eq "-tx" ) {
        ClearTokenCache
        exit
    } elseif ( $arg1 -eq "-v" ) {
        PrintUsage
    }
    SetupApiTokens  # Remaining ones will need API tokens set up
    if ( $arg1 -eq "-z" ) {
        DumpVariables
    }
} elseif ( $args.Count -eq 2 ) {    # Process 2-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    SetupApiTokens
    if ( $arg1 -eq "-vs" ) {
        DisplayGroup $arg2
    } elseif ( $arg1 -eq "-rm" ) {
        DeleteGroup $arg2
    } elseif ( $arg1 -eq "-up" ) {
        CreateAzGroup $arg2  # Create group with 1 arguments
    } else {
        PrintUsage    
    }
} elseif ( $args.Count -eq 3 ) {    # Process 3-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    if ( $arg1 -eq "-cri" ) {
        SetupInteractiveLogin $arg2 $arg3
    } elseif ( $arg1 -eq "-up" ) {
        SetupApiTokens
        CreateAzGroup $arg2 $arg3  # Create group with 2 arguments
    } else {
        PrintUsage    
    }
} elseif ( $args.Count -eq 4 ) {    # Process 4-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    $arg4 = $args[3]
    if ( $arg1 -eq "-cr" ) {
        SetupAutomatedLogin $arg2 $arg3 $arg4
    } elseif ( $arg1 -eq "-up" ) {
        SetupApiTokens
        CreateAzGroup $arg2 $arg3 $arg4  # Create group with 3 arguments
    } else {
        PrintUsage    
    }
} elseif ( $args.Count -eq 4 ) {    # Process 5-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    $arg4 = $args[3]
    $arg5 = $args[4]
    if ( $arg1 -eq "-up" ) {
        SetupApiTokens
        CreateAzGroup $arg2 $arg3 $arg4 $arg5  # Create group with 4 arguments
    } else {
        PrintUsage    
    }
} else {
    PrintUsage
}
