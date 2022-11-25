# App-Sp-Pair-Create.ps1
# You may need to manually install the MS Graph module: Install-Module Microsoft.Graph

param (
    [string] $name
)

function die($msg) {
    Write-Host -ForegroundColor Yellow $msg ; Exit
}

function print_usage() {
    die "`nUsage:`n  $prgName DISPLAY_NAME`n"
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
$prgName = (Get-PSCallStack)[0].Command.Split(".")[0]

if ([string]::IsNullOrWhiteSpace($name)) {
    print_usage  # User must supply at least a DisplayName
}

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

# Disconnect-MgGraph  # To clean up your cached login
