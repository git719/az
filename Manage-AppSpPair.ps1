# Manage-AppSpPair.ps1

# Global variables
$global:prgname         = "Manage-AppSpPair"
$global:prgver          = "0.4.0"
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
    "sp" = "servicePrincipals"
    "ap" = "applications"
}

# =================== HOUSEKEEPING FUNCTIONS =======================
function PrintUsage() {
    die("$prgname Azure App/SP combo manager v$prgver`n" +
        "    -vs Name|AppUUID                  Display existing App/SP pair with given displayName or App UUID`n" +
        "    -rm Name|AppUUID                  Delete existing App/SP pair with given displayName or App UUID`n" +
        "    -up Name                          Create App/SP pair with given displayName`n" +
        "`n" +
        "    -z                                Dump variables in running program`n" +
        "    -cr                               Dump values in credentials file`n" +
        "    -cr  TenantId ClientId Secret     Set up MSAL automated client_id + secret login`n" +
        "    -cri TenantId Username            Set up MSAL interactive browser popup login`n" +
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

function ImportMod($m) {
    # Base on https://stackoverflow.com/questions/28740320/how-do-i-check-if-a-powershell-module-is-installed?answertab=active
    if (Get-Module | Where-Object {$_.Name -eq $m}) {
        # warning("==> Module $m is already imported.")
    } else {
        if (Get-Module -ListAvailable | Where-Object {$_.Name -eq $m}) {
            # warning("==> Module $m is available on disk. Importing now ...")
            Import-Module $m
        } else {
            if (Find-Module -Name $m -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq $m}) {
                warning("`n==> Installing module $m from online gallery, and importing ...`n")
                Install-Module -Name $m -Scope CurrentUser -Force -AllowClobber
                Import-Module $m
            } else {
                die("`n==> Error, module $m not imported, not available from local disk, and not in online gallery.`n")
            }
        }
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
    $global:confdir = Join-Path -Path $homeDir -ChildPath (".maz")
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

function DeleteMgObject($t, $x) {
    # Delete MS Graph object type $t
    $url = $mg_url + "/v1.0/" + $oMap[$t] + "/" + $x.id
    $r = ApiCall "DELETE" ($url) -quiet
    if ( ($null -ne $r) -and ($r.StatusCode -ne 204) ) {
        die("Error deleting object $($x.id)")
    }
}

function MgObjectExists($t, $displayName) {
    # Check if object of type $t with this displayName exists
    $headers = @{ "ConsistencyLevel" = "eventual" }
    $r = ApiCall "GET" ($mg_url + "/v1.0/" + $oMap[$t] + "?`$search=`"displayName:" + $displayName + "`"&`$count=true") -headers $headers -quiet
    if ( $r.'@odata.count' -gt 0 ) {
        return $true
    }
}

function GetMgObject($t, $specifier) {
    # Get existing object of type $t
    $headers = @{ "ConsistencyLevel" = "eventual" }
    if ( ValidUuid $specifier ) {
        $url = "/v1.0/" + $oMap[$t] + "?`$search=`"appId:" + $specifier + "`"&`$count=true"
    } else {
        $url = "/v1.0/" + $oMap[$t] + "?`$search=`"displayName:" + $specifier + "`"&`$count=true"
    }
    $r = ApiCall "GET" ($mg_url + $url) -headers $headers -quiet
    if ( $r.'@odata.count' -gt 0 ) {
        return $r
    }
    return $null
}

function CreateApp($displayName) {
    # Create a new App in this tenant
    $payload = @{ "displayName" = $displayName } | ConvertTo-Json
    $r = ApiCall "POST" ($mg_url + "/v1.0/applications") -data $payload
    if ( ($null -eq $r) -or ($null -eq $r.id ) ) {
        die("Error. Creating application.")
    }
    return $r
}

function CreateAppSecret($appObjectId) {
    # Generate a new secret for given App Object ID
    $payload = @{
        displayName = (Get-Date)
        endDateTime = (Get-Date).AddMonths(12)  # Default to 1 year Expiry
    } | ConvertTo-Json
    $r = ApiCall "POST" ($mg_url + "/v1.0/applications/" + $appObjectId + "/addPassword") -data $payload
    if ( ($null -eq $r) -or ($null -eq $r.secretText ) ) {
        die("Error. Creating secret for application with Object Id '$appObjectId'.")
    }
    return $r.secretText
}

function CreateSp($appId) {
    # Create a new SP in this tenant
    $payload = @{ "appId" = $appId } | ConvertTo-Json
    $r = ApiCall "POST" ($mg_url + "/v1.0/servicePrincipals") -data $payload
    if ( ($null -eq $r) -or ($null -eq $r.id ) ) {
        die("Error. Creating SP for appId '$appId'.")
    }
    return $r
}

# =================== PROGRAM FUNCTIONS =======================
function DisplayPair($specifier) {
    $ap = GetMgObject "ap" $specifier
    # Note that GetMgObject can return more than one object
    if ( ($null -ne $ap.'@odata.count') -and ($ap.'@odata.count' -gt 1) ) {
        print("APP: There's more than one App with this same displayName")
    } elseif ( ($null -ne $ap.'@odata.count') -and
               ( ($ap.value[0].displayName -eq $specifier) -or ($ap.value[0].appId -eq $specifier) ) ) {
        print("APP: Exists, and has Object Id = {0}" -f $ap.value[0].id)
    } else {
        print("APP: Does NOT exist")
    }
    $sp = GetMgObject "sp" $specifier
    if ( ($null -ne $sp.'@odata.count') -and ($sp.'@odata.count' -gt 1) ) {
        print("SP : There's more than one SP with this same displayName")
    } elseif ( ($null -ne $sp.'@odata.count') -and
               ( ($sp.value[0].displayName -eq $specifier) -or ($sp.value[0].appId -eq $specifier) ) ) {
        print("SP : Exists, and has Object Id = {0}" -f $sp.value[0].id)
    } else {
        print("SP : Does NOT exist")
    }
    exit
}

function DeletePrompt($t, $x) {
    $confirm = Read-Host -Prompt "DELETE above? y/n"
    if ( $confirm -eq "y" ) {
        DeleteMgObject $t $x
    }
}

function DeletePair($specifier) {
    # Delete App/SP pair if they exist based on string specifier
    $scount = 0
    $x = GetMgobject "ap" $specifier
    # Prompt to delete the Application, which should delete the SP also
    if ( ($null -ne $x. '@odata.count') -and
         ( ($x.value[0].displayName -eq $specifier) -or ($x.value[0].appId -eq $specifier) ) ) {
        $count += 1
        print ("`nAPP displayName = $($x.value[0].displayName)")
        print ("APP objectId    = $($x.value[0].id)")
        print ("APP appId       = $($x.value[0].appId)`n")
        DeletePrompt "ap" $x.value[0]
    }
    $x = GetMgobject "sp" $specifier
    # Still check if an SP with this specifier needs deleting
    if ( $null -ne $x ) {
        $count += 1
        print("`nSP displayName  = $($x.value[0].displayName)")
        print("SP objectId     = $($x.value[0].id)")
        print("SP appid        = $($x.value[0].appId)`n")
        DeletePrompt "sp" $x.value[0]
    }
    if ( $count -eq 0 ) {
        die("There's no App or SP with specifier = $specifier")
    }
}

function CreatePair($displayName) {
    # Create app + SP pair combo
    if ( MgObjectExists "ap" $displayName ) {
        die("Error. An application named `"$displayName`" already exists.")
    }
    if ( MgObjectExists "sp" $displayName ) {
        die("Error. A Service Principal named `"$displayName`" already exists.")
    }
    $new_app = CreateApp $displayName
    $secret = CreateAppSecret $new_app.id
    $new_sp = CreateSp $new_app.appId
    print("`nAPP/SP   = $($new_app.DisplayName)")
    print("AppId    = $($new_sp.appId)")
    print("TenantId = $($tenant_id)")
    print("Secret   = `"$secret`" (PROTECT ACCORDINGLY!)`n")
}

# =================== MAIN ===========================
ImportMod "powershell-yaml"
ImportMod "MSAL.PS"
if ( ($args.Count -lt 1) -or ($args.Count -gt 4) ) {
    PrintUsage  # Don't accept less than 1 or more than 4 arguments
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
    # Remaining ones will need API tokens set up
    SetupApiTokens
    if ( $arg1 -eq "-z" ) {
        DumpVariables
    }
} elseif ( $args.Count -eq 2 ) {    # Process 2-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    SetupApiTokens
    if ( $arg1 -eq "-vs" ) {
        DisplayPair $arg2
    } elseif ( $arg1 -eq "-rm" ) {
        DeletePair $arg2
    } elseif ( $arg1 -eq "-up" ) {
        CreatePair $arg2
    } else {
        PrintUsage
    }
} elseif ( $args.Count -eq 3 ) {    # Process 3-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    if ( $arg1 -eq "-cri" ) {
        SetupInteractiveLogin $arg2 $arg3
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
    } else {
        PrintUsage
    }
} else {
    PrintUsage
}
