# SP-Auth.ps1

# Work in progress 

# Global variables
$global:prgname         = "SP-Auth"
$global:prgver          = "3"
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

function die($msg) {
    Write-Host -ForegroundColor Yellow $msg ; exit
}

function print_usage() {
    die ("$prgname Azure SP API permissions utility v$prgver`n" +
        "        SP_OBJECT_UUID                        Display Service Principal API permissions`n" +
        "        -a oAuth2PermissionGrant_object.json  Create oAuth2PermissionGrant based on file`n" +
        "        -k                                    Create a skeleton oAuth2PermissionGrant_object.json file`n" +
        "        ID                                    Display oAuth2PermissionGrants object`n" +
        "        -d ID                                 Delete oAuth2PermissionGrants ID`n" +
        "        ID `"space-separated claims list`"      Update oAuth2PermissionGrants ID with provided claims list`n" +
        "        -cr                                   Dump values in credentials file`n" +
        "        -cr  TENANT_ID CLIENT_ID SECRET       Set up MSAL automated client_id + secret login`n" +
        "        -cri TENANT_ID USERNAME               Set up MSAL interactive browser popup login`n" +
		"        -tx                                   Delete MSAL accessTokens cache file")
}

function panic($s) {
    Write-Host "Pass"
}

function file_exist($filePath) {
    Write-Host "Pass"
}

function file_size($filePath) {
    Write-Host "Pass"
}

function remove_file($filePath) {
    Write-Host "Pass"
}

function load_file_yaml($filePath) {
    Write-Host "Pass"
}

function load_file_json($filePath) {
    Write-Host "Pass"
}

function save_file_json($jsonObject, $filePath) {
    Write-Host "Pass"
}

function print_json($jsonObject) {
    Write-Host "Pass"
}

function valid_uuid($id) {
    Write-Host "Pass"
}

function create_skeleton() {
    Write-Host "Pass"
}

function dump_variables() {
    Write-Host "Pass"
}

function dump_credentials() {
    Write-Host "Pass"
}

function setup_interactive_login($tenant_id, $username) {
    Write-Host "Pass"
}

function setup_automated_login($tenant_id, $client_id, $secret) {
    Write-Host "Pass"
}

function setup_credentials() {
    Write-Host "Pass"
}

function setup_api_tokens() {
    Write-Host "Pass"
}

function get_token($scopes) {
    Write-Host "Pass"
}

function api_get($resource, $headers=$null, $params=$null, $verbose=$false) {
    Write-Host "Pass"
}

function api_delete($resource, $headers=$null, $params=$null, $verbose=$false, $data=$null) {
    Write-Host "Pass"
}

function api_patch($resource, $headers=$null, $params=$null, $verbose=$false, $data=$null) {
    Write-Host "Pass"
}

function api_post($resource, $headers=$null, $params=$null, $verbose=$false, $data=$null) {
    Write-Host "Pass"
}

function show_sp_perms($id) {
    Write-Host "Pass"
}

function valid_oauth_id($id) {
    Write-Host "Pass"
}

function show_perms($id) {
    Write-Host "Pass"
}

function update_perms($id, $claims) {
    Write-Host "Pass"
}

function delete_perms($id) {
    Write-Host "Pass"
}

function create_perms($filePath) {
    Write-Host "Pass"
}

function setup_confdir () {
    # Create the utility's config directory
    # $env:USERPROFILE = $pwd    # Test with working dir
    if ( $null -eq $env:USERPROFILE ) {
        die "Missing USERPROFILE environment variable"
    } else {
        $global:confdir = Join-Path -Path $env:USERPROFILE -ChildPath ("." + $prgname)
        Write-Host $global:confdir
        if (-not (Test-Path -LiteralPath $global:confdir)) {
            try {
                New-Item -Path $global:confdir -ItemType Directory -ErrorAction Stop | Out-Null #-Force
            }
            catch {
                die "Unable to create directory '$global:confdir'. Error was: $_"
            }
        }
    }
}

# =================== MAIN ===========================
if ( ($args.Count -lt 1) -or ($args.Count -gt 4) ) {
    print_usage  # Don't accept less than 1 or more than 4 arguments
}

setup_confdir

if ( $args.Count -eq 1 ) {        # Process 1-argument requests
    $arg1 = $args[0]
    setup_api_tokens
    if ( valid_uuid $arg1 ) {
        show_sp_perms $arg1 
    } elseif ( $arg1 -eq "-k" ) {
        create_skeleton
    } elseif ( $arg1 -eq "-tx" ) {
        remove_file #os.path.join(confdir, "accessTokens.json") 
    } elseif ( $arg1 -eq "-z" ) {
        dump_variables
    } elseif ( $arg1 -eq "-cr" ) {
        dump_credentials
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
    } else {
        update_perms $arg1 $arg2
    }
} elseif ( $args.Count -eq 3 ) {  # Process 3-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    if ( $arg1 -eq "-cri" ) {
        setup_interactive_login $arg2 $arg3
    }
} elseif ( $args.Count -eq 4 ) {  # Process 4-argument requests
    $arg1 = $args[0]
    $arg2 = $args[1]
    $arg3 = $args[2]
    $arg4 = $args[3]
    if ( $arg1 -eq "-cr" ) {
        setup_automated_login $arg2 $arg3 $arg4
    }
} else {
    print_usage
}
