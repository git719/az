# SP-Auth.ps1

# Work in progress 

# We're interested in the raw arguments as they were passed
# See https://stackoverflow.com/questions/59657293/how-to-check-number-of-arguments-in-powershell

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

function CreateAppSP($name) {
    # Ensure there is no existing application and/or service principal using this same displayName
    $id = (Get-MgApplication -ConsistencyLevel eventual -Search "DisplayName:$name").Id
    if ($null -ne $id) {
        die "Application `"$name`" already exists. Aborting."
    }
    $id = (Get-MgServicePrincipal -ConsistencyLevel eventual -Search "DisplayName:$name").Id
    if ($null -ne $id) {
        die "Service Principal `"$name`" already exists. Aborting."
    }
    Write-Host "... creating a same-name registered app + SP combo and a secret for that SP ..."
    $new_app = New-MgApplication -DisplayName $name # Optional: -Tags "key1 = value1, key2 = value2"

    $passwordCred = @{
        displayName = (Get-Date)
        endDateTime = (Get-Date).AddMonths(12)
    }
    $secret = Add-MgApplicationPassword -ApplicationId $new_app.Id -PasswordCredential $passwordCred

    $new_sp = New-MGServicePrincipal -AppId $new_app.AppId
    Write-Host "APP/SP  = $($new_app.DisplayName)"
    Write-Host "APPID   = $($new_sp.AppId)"
    Write-Host "SECRET  = `"$($secret.SecretText)`" (PROTECT ACCORDINGLY!)"
}

# =================== MAIN ===========================
if ( ($args.Count -lt 1) -or ($args.Count -gt 4) ) {
    print_usage  # Don't accept less than 1 or more than 4 arguments
}

# Create utility config directory
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

die "Done"


# Set up required scopes and connect to MS Graph
$scopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
    # See https://docs.microsoft.com/en-us/graph/permissions-reference#application-permissions-49
)
Connect-MgGraph -Scope $scopes | Out-Null

# Note, this module simply uses the "Microsoft Graph PowerShell" (AppId=14d82eec-204b-4c2f-b7e8-296a70dab67e) Enterprise
# application in the tenant. User will need to Accept Consent, which will add them to the list of Users for this app.
# Of course, only users that have the required privilege in the tenant will be able to do this.

$sessionInfo = Get-MgContext
$tenant_id = $sessionInfo.TenantId
Write-Host "TENANT  = $tenant_id"

CreateAppSP $name
Disconnect-MgGraph  # To clean up your cached login
