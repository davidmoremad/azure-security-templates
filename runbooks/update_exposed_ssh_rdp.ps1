<#
.SYNOPSIS
    Update public SSH/RDP to private networks
.DESCRIPTION
    Critical ports must be closed to public IP rages to avoid exposures.
    In order to perform this, there is a safe-IPs list ($parameters) and
    if source-address does not match, creation will be denied. 
    If you need more information, please contact DevOps team.
.NOTES
    Author: David Amrani Hernandez
.LINK
    https://github.com/davidmoremad/azure-security-templates
#>

# EDIT THIS LINE WITH YOUR SAFE IPS
# These IPs will be allowed to access using SSH / RDP
[string[]]$ips = @("10.11.12.13/32","20.21.22.23/32")


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
Write-Output "Subscriptions"
Write-Output $ids


# 3. Runbook functionality
##############################################
For ($i=0; $i -lt $ids.Length; $i++) {
    
    # Getting Security Groups
    $nsgs = Get-AzNetworkSecurityGroup
    $nsgs | ForEach-Object {

        $nsg_id = $_.Id
        $nsg_name = $_.Name
        $nsg_rg = $_.ResourceGroupName
        
        $_.SecurityRules | ForEach-Object {

            # Check if SSH/RDP rule is exposed to Internet
            if ($_.Access -eq "Allow" -and ($_.DestinationPortRange -eq "22" -or $_.DestinationPortRange -eq "22-22") -and ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0" -or $_.SourceAddressPrefix -eq "0.0.0.0/0" -or $_.SourceAddressPrefix -eq "Internet"))
            {
                # Updating rule to private IPS
                Get-AzNetworkSecurityGroup -Name $nsg_name -ResourceGroupName $nsg_rg | Set-AzNetworkSecurityRuleConfig -Name $_.Name -Access $_.Access -Protocol $_.Protocol -Direction $_.Direction -Priority $_.Priority -SourceAddressPrefix $ips -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange "22" | Set-AzNetworkSecurityGroup
                Write-Output "SSH Exposed! - Updating to private networks. ID: $nsg_id"
            }

            if ($_.Access -eq "Allow" -and ($_.DestinationPortRange -eq "3389" -or $_.DestinationPortRange -eq "3389-3389") -and ($_.SourceAddressPrefix -eq "*" -or $_.SourceAddressPrefix -eq "0.0.0.0" -or $_.SourceAddressPrefix -eq "0.0.0.0/0" -or $_.SourceAddressPrefix -eq "Internet"))
            {
                # Updating rule to private IPS
                Get-AzNetworkSecurityGroup -Name $nsg_name -ResourceGroupName $nsg_rg | Set-AzNetworkSecurityRuleConfig -Name $_.Name -Access $_.Access -Protocol $_.Protocol -Direction $_.Direction -Priority $_.Priority -SourceAddressPrefix $ips -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange "3389" | Set-AzNetworkSecurityGroup
                Write-Output "RDP Exposed! - Updating to private networks. ID: $nsg_id"
            }
        }
    }
}