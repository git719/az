# Group-Create.ps1

# You may need to manually install the MS Graph module: Install-Module Microsoft.Graph

param (
    [string] $name,
    [string] $description = " ",
    [string] $owner = " ",
    [switch] $assignable
)

function print_usage() {
    Write-Host "Usage:"
    Write-Host "  $prgName -name 'GroupDisplayname' [-description 'Description'] [-owner 'user@domain.com'] [-assignable]"
    Exit
}

function create_group ($name, $description, $owner, $assignable) {
    $id = (Get-MgGroup -ConsistencyLevel eventual -Search "DisplayName:$name").Id
    if ($null -ne $id) {
        Write-Host -ForegroundColor Yellow "Group '$name' ($id) already exists. Aborting."
        Exit
    }
    $properties = @{
        "displayName"        = $name;
        "description"        = $description;
        "securityEnable"     = $true;
        "isAssignableToRole" = $assignable
    }
    New-MgGroup -AdditionalProperties $properties
}

# =================== MAIN ===========================
$prgName = (Get-PSCallStack)[0].Command.Split(".")[0]

if ([string]::IsNullOrWhiteSpace($name)) {
    # Minimally we need a GroupDisplayName
    print_usage
}
Write-Host "============== Parameters ============"
Write-Host "Group Name   = [$name]"
Write-Host "Description  = [$description]"


# Logon to MS Graph
Connect-MgGraph -Scope "Group.ReadWrite.All"
# You'll need to Accept Consent, which will add you to the list of Users for this app. Note, this module
# simply users the "Microsoft Graph PowerShell" (AppId=14d82eec-204b-4c2f-b7e8-296a70dab67e) Enterprise
# application in the tenant. So that app needs to be already setup to use this PS module.

$sessionInfo = Get-MgContext
$tenant_id = $sessionInfo.TenantId
if ([string]::IsNullOrWhiteSpace($owner)) {
    $owner = $sessionInfo.Account  # If no owner provided, use the currently logged in user
}

Write-Host "Owner        = [$owner]"
Write-Host "Assignable   = [$assignable]"
Write-Host "Tenant_Id    = [$tenant_id]"
Write-Host "======================================"

$new_group = create_group $name $description $owner $assignable
$new_group 

# Disconnect-MgGraph  # Clean up
