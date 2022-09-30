# App-Sp-Pair-Create.ps1

# You may need to manually install the MS Graph module: Install-Module Microsoft.Graph

param (
    [string] $name
)

function print_usage() {
    Write-Host "`nUsage:"
    Write-Host "  $prgName DISPLAY_NAME`n"
    Exit
}

function CreateAppSP($name) {
    # Ensure there is no existing application and/or service principal using this same displayName
    $problem = $false
    $id = (Get-MgApplication -ConsistencyLevel eventual -Search "DisplayName:$name").Id
    if ($null -ne $id) {
        Write-Host -ForegroundColor Yellow "`nApplication `"$name`" already exists. Aborting."
        $problem = $true
    }
    $id = (Get-MgServicePrincipal -ConsistencyLevel eventual -Search "DisplayName:$name").Id
    if ($null -ne $id) {
        Write-Host -ForegroundColor Yellow "`nService Principal `"$name`" already exists. Aborting."
        $problem = $true
    }
    if ($problem) {
        Exit
    }
    Write-Host "1) Creating a registered application, 2) generating a new secret for it, and 3) creating accompanying service principal ..."
    $new_app = New-MgApplication -DisplayName $name # Optional: -Tags "key1 = value1, key2 = value2"
    Write-Host "1) APP    : $($new_app.DisplayName) | AppId = $($new_app.AppId) | ObjectId = $($new_app.Id)"

    $passwordCred = @{
        displayName = (Get-Date)
        endDateTime = (Get-Date).AddMonths(12)
    }
    $secret = Add-MgApplicationPassword -ApplicationId $new_app.Id -PasswordCredential $passwordCred
    Write-Host "2) SECRET : `"$($secret.SecretText)`" | Name = `"$($secret.DisplayName)`" | Expiry = `"$($secret.EndDateTime)`""

    $new_sp = New-MGServicePrincipal -AppId $new_app.AppId
    Write-Host "3) SP     : $($new_sp.DisplayName) | AppId = $($new_sp.AppId) | ObjectId = $($new_sp.ID)"
}

# =================== MAIN ===========================
$prgName = (Get-PSCallStack)[0].Command.Split(".")[0]

if ([string]::IsNullOrWhiteSpace($name)) {
    # Minimally we need a DisplayName
    print_usage
}
Write-Host "`n-------------- Parameters ------------"
Write-Host "App/SP DisplayName   = `"$name`""
Write-Host "Tenant_ID            = $tenant_id"

# Set up rquired scopes and connect to MS Graph
$scopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All"
    # See https://docs.microsoft.com/en-us/graph/permissions-reference#application-permissions-49
)
Connect-MgGraph -Scope $scopes | Out-Null

# Note, this module simply uses the "Microsoft Graph PowerShell" (AppId=14d82eec-204b-4c2f-b7e8-296a70dab67e) Enterprise
# application in the tenant. User will need to Accept Consent, which will add them to the list of Users for this app.

$sessionInfo = Get-MgContext
$tenant_id = $sessionInfo.TenantId

Write-Host "Tenant_ID            = $tenant_id"
Write-Host "--------------------------------------"

CreateAppSP $name

# Disconnect-MgGraph  # Clean up
