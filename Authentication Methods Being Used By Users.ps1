# Connect
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "User.Read.All"

# Get context and setup output
$context = Get-MgContext
$outputPath = "C:\Forensics"
if (!(Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

# Get all users
$allUsers = Get-MgUser -All -Property UserPrincipalName, DisplayName, Id

$results = foreach ($user in $allUsers) {
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
    
    $methodList = @()
    foreach ($method in $methods) {
        $type = $method.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.', ''
        $methodList += $type
    }
    
    # Check if they have ONLY phone/SMS (no stronger MFA methods)
    $hasStrongMFA = $methodList | Where-Object {
        $_ -in @('microsoftAuthenticatorAuthenticationMethod', 'fido2AuthenticationMethod', 'windowsHelloForBusinessAuthenticationMethod', 'softwareOathAuthenticationMethod')
    }
    
    $hasPhoneSMS = ($methodList -contains 'phoneAuthenticationMethod' -or 
                    $methodList -contains 'smsAuthenticationMethod')
    
    [PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        DisplayName = $user.DisplayName
        AuthenticationMethods = ($methodList -join '; ')
        OnlySMSOrPhone = ($hasPhoneSMS -and !$hasStrongMFA)
    }
}

# Filter to only users with weak MFA
$usersWithOnlyPhoneMFA = $results | Where-Object { $_.OnlySMSOrPhone -eq $true }

# Export
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$tenantShort = $context.TenantId.Substring(0,8)
$exportFile = Join-Path $outputPath "UsersWithOnlyPhoneMFA_${tenantShort}_${timestamp}.csv"
$usersWithOnlyPhoneMFA | Export-Csv -Path $exportFile -NoTypeInformation
Write-Host "[✓] Results exported to: $exportFile" -ForegroundColor Green
Write-Host "[!] Found $($usersWithOnlyPhoneMFA.Count) users with only SMS/Phone MFA" -ForegroundColor Yellow