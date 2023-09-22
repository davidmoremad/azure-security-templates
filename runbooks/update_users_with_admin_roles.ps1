<#
.SYNOPSIS
    Update Owner roles to Owner Sec.
.DESCRIPTION
    Owner or contributor roles are not allowed due to a overextended
    permissions, so we've created a new ones that are safer.
    If you need more information, please contact DevOps team.
.NOTES
    Author: David Amrani Hernandez
.LINK
    https://github.com/davidmoremad/azure-security-templates
#>

# EDIT THIS LINE WITH YOUR OWN ROLES
# Default roles (owner & contributor) will be replaced with these ones
# First you need to create your custom roles Owner Sec and Contributor Sec in every subscription
# REMEMBER: These are the role NAMES!
[string]$ownerRoleNameReplacement = "Owner Sec"
[string]$contributorRoleNameReplacement = "Contributor Sec"

# 1. Connect using a Managed Service Identity
##############################################
Disable-AzContextAutosave -Scope Process | Out-Null # Ensures you do not inherit an AzContext in your runbook
try {
    $AzureContext = (Connect-AzAccount -Identity).context
}
catch {
    Write-Output "There is no system-assigned user identity. Aborting."; 
    exit
}
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext


# 2. Gathering information
##############################################
$tenantId = [string](Get-AzSubscription | Select-Object -first 1).TenantId
$ids = [string[]](Get-AzSubscription -TenantId $tenantId).SubscriptionId


# 3. Runbook functionality
##############################################
For ($i=0; $i -lt $ids.Length; $i++) {
    $id = $ids[$i]

    Write-Output "Running policy over subscription $id"
    Get-AzSubscription -SubscriptionId $id -TenantId $tenantId | Set-AzContext

    # List objects with role Owner
    $roles = [object[]](Get-AzRoleAssignment -RoleDefinitionName "Owner")
    Write-Output "Users with role Owner: "  $roles.Count
    if ($roles.Count -gt 0)
    {
        $roles | ForEach-Object {

            $scope = $_.Scope
            $object_id = $_.ObjectId

            Try {
                # Assign Owner-Sec to object
                $t = New-AzRoleAssignment -ObjectId $object_id -Scope $scope -RoleDefinitionname $ownerRoleNameReplacement
                
                if ($t -ne "" -and $t -ne $null)
                {
                    # Removing Owner permission
                    Write-Output "User $object_id updated from Owner to Owner Sec"
                    Remove-AzRoleAssignment -ObjectId $object_id -RoleDefinitionname "Owner" -Scope $scope
                }
            }
            Catch {
                $_
            }
        }
    }

    # List objects with role Contributor
    $roles = [object[]](Get-AzRoleAssignment -RoleDefinitionName "Contributor")
    Write-Output "Users with role Contributor: "  $roles.Count
    if ($roles.Count -gt 0)
    {
        $roles | ForEach-Object {

            $scope = $_.Scope
            $object_id = $_.ObjectId

            Try {
                # Assign Contributor-Sec to object
                $t = New-AzRoleAssignment -ObjectId $object_id -Scope $scope -RoleDefinitionname $contributorRoleNameReplacement
                
                if ($t -ne "" -and $t -ne $null)
                {
                    # Removing Contributor permission
                    Write-Output "User $object_id updated from Contributor to Contributor Sec"
                    Remove-AzRoleAssignment -ObjectId $object_id -RoleDefinitionname "Contributor" -Scope $scope
                }
            }
            Catch {
                $_
            }
        }
    }


}