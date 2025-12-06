Connect-MgGraph

# Get all users
Write-Host "Fetching all users..." -ForegroundColor Cyan
$users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName

Write-Host "Found $($users.Count) users. Checking MFA enrollment..." -ForegroundColor Cyan

$notEnrolled = @()

foreach ($user in $users) {
    # Get authentication methods for each user
    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
    
    # Filter out password-only methods (password alone doesn't count as MFA)
    $mfaMethods = $authMethods | Where-Object { 
        $_.AdditionalProperties.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' 
    }
    
    # If no MFA methods found, add to list
    if ($mfaMethods.Count -eq 0) {
        $notEnrolled += [PSCustomObject]@{
            DisplayName       = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Id                = $user.Id
        }
        Write-Host "  - $($user.UserPrincipalName) - Not enrolled" -ForegroundColor Yellow
    }
}

# Display summary
Write-Host "`nSummary:" -ForegroundColor Green
Write-Host "Total users: $($users.Count)" -ForegroundColor White
Write-Host "Users NOT enrolled in MFA: $($notEnrolled.Count)" -ForegroundColor Red

# Display the results
$notEnrolled | Format-Table -AutoSize

# Export to CSV with tenant ID in filename $timestamp = Get-Date -Format "yyyyMMdd-HHmmss" $tenantShort = $context.TenantId.Substring(0,8) $exportFile = Join-Path $outputPath "UsersNotEnrolledForMFA_$tenantShort_$timestamp.csv" $notEnrolled | Export-Csv -Path $exportFile -NoTypeInformation Write-Host "[✓] Results exported to: $exportFile" -ForegroundColor Green
