<#
.SYNOPSIS
    Example: Onboard an Active Directory account into CyberArk PAM.

.DESCRIPTION
    This script:
      1. Reads a user from Active Directory
      2. Authenticates to CyberArk PVWA REST API
      3. Adds the AD account into a CyberArk Safe
      4. Uses platform properties commonly associated with
         "Windows Domain Accounts via LDAP"

.NOTES
    - This is a learning example for security engineers.
    - Adjust field names, platform IDs, and API auth method to match your environment.
    - Never hardcode production passwords in source code.
#>

# -----------------------------
# SECTION 1 - CONFIGURATION
# -----------------------------

# CyberArk PVWA base URL
$PvwaBaseUrl = "https://pvwa.company.com"

# CyberArk authentication endpoint
# In many environments, a CyberArk-authentication path like this is used.
# Your environment may use LDAP, SAML, RADIUS, or another auth method instead.
$LogonUrl = "$PvwaBaseUrl/PasswordVault/API/Auth/CyberArk/Logon"

# CyberArk add-account endpoint
$AddAccountUrl = "$PvwaBaseUrl/PasswordVault/API/Accounts"

# Target AD user to onboard
$TargetSamAccountName = "svc_sqlbackup"

# Safe where the account will be stored
$SafeName = "Windows-Domain-Accounts"

# Platform ID in CyberArk
# IMPORTANT:
# Verify the exact platform ID in your CyberArk environment.
# CyberArk docs show platform IDs are case-sensitive.
$PlatformId = "WinDomain"

# Domain controller / LDAP address CyberArk will manage against
# For the Windows Domain Accounts via LDAP platform, the "address"
# is the directory address.
$DirectoryAddress = "dc1.corp.company.com"

# NetBIOS domain (required when using sAMAccountName format on this platform)
$LogonDomain = "CORP"

# -----------------------------
# SECTION 2 - GET AD USER
# -----------------------------
# Requires RSAT ActiveDirectory module on the machine running the script.

Import-Module ActiveDirectory -ErrorAction Stop

try {
    # Pull the user from AD
    $AdUser = Get-ADUser -Identity $TargetSamAccountName -Properties UserPrincipalName, DistinguishedName, Enabled

    if (-not $AdUser) {
        throw "AD user '$TargetSamAccountName' was not found."
    }

    if (-not $AdUser.Enabled) {
        Write-Warning "The AD user exists but is disabled."
    }

    Write-Host "Found AD user:"
    Write-Host "  sAMAccountName : $($AdUser.SamAccountName)"
    Write-Host "  UPN            : $($AdUser.UserPrincipalName)"
    Write-Host "  DN             : $($AdUser.DistinguishedName)"
}
catch {
    throw "Failed to query Active Directory. Error: $($_.Exception.Message)"
}

# -----------------------------
# SECTION 3 - GET CYBERARK CREDENTIALS
# -----------------------------

# Prompt securely for the CyberArk admin/operator username
$CyberArkUsername = Read-Host "Enter CyberArk username"

# Prompt securely for password
$SecureCyberArkPassword = Read-Host "Enter CyberArk password" -AsSecureString

# Convert SecureString to plain text only for the API call
# WARNING: Do this as briefly as possible and avoid logging it.
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureCyberArkPassword)
$PlainCyberArkPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

# -----------------------------
# SECTION 4 - LOG ON TO CYBERARK
# -----------------------------
try {
    # Build the logon body
    # CyberArk logon endpoints return a session token, which must be sent
    # in the Authorization header for later API calls.
    $LogonBody = @{
        username = $CyberArkUsername
        password = $PlainCyberArkPassword
    } | ConvertTo-Json

    $CyberArkToken = Invoke-RestMethod `
        -Uri $LogonUrl `
        -Method Post `
        -ContentType "application/json" `
        -Body $LogonBody

    if (-not $CyberArkToken) {
        throw "No CyberArk token was returned by the logon API."
    }

    Write-Host "Successfully authenticated to CyberArk."
}
catch {
    throw "CyberArk authentication failed. Error: $($_.Exception.Message)"
}
finally {
    # Clean up plaintext password variable quickly
    $PlainCyberArkPassword = $null
}

# -----------------------------
# SECTION 5 - BUILD ACCOUNT PAYLOAD
# -----------------------------
# CyberArk's Add Account API accepts fields such as:
#   name, address, userName, platformId, safeName, secretType, secret,
#   platformAccountProperties, secretManagement, etc.
#
# For the Windows Domain Accounts via LDAP plugin/platform, CyberArk docs
# describe parameters such as:
#   AuthenticationType, LogonDomain, Port, UseSSL, StartTLS, UnlockUserOnReconcile
#
# The username can be UPN or sAMAccountName. If using sAMAccountName,
# LogonDomain must contain the NetBIOS domain name.

# NOTE:
# Some organizations let CyberArk immediately manage the password.
# Others onboard with manual management first, then enable CPM later.
# Here we show automatic management enabled.

$AccountPayload = @{
    name       = "AD-$($AdUser.SamAccountName)"
    address    = $DirectoryAddress
    userName   = $AdUser.SamAccountName
    platformId = $PlatformId
    safeName   = $SafeName

    # In many onboarding flows you may include the current secret.
    # For security reasons, this demo prompts separately.
    secretType = "password"
    secret     = (Read-Host "Enter CURRENT password for target AD account" -AsSecureString |
        ForEach-Object {
            $tmp = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($tmp)
        })

    # Platform-specific properties
    platformAccountProperties = @{
        LogonDomain            = $LogonDomain
        AuthenticationType     = "Basic"
        Port                   = "636"
        UseSSL                 = "Yes"
        StartTLS               = "No"
        UserDN                 = $AdUser.DistinguishedName
        UnlockUserOnReconcile  = "Yes"
    }

    # Enable CyberArk CPM automatic password management
    secretManagement = @{
        automaticManagementEnabled = $true
    }

    # Optional remote machine restrictions could be added here if needed
    remoteMachinesAccess = @{
        remoteMachines = ""
        accessRestrictedToRemoteMachines = $false
    }

} | ConvertTo-Json -Depth 6

# -----------------------------
# SECTION 6 - ADD ACCOUNT TO CYBERARK
# -----------------------------
try {
    $Headers = @{
        Authorization = $CyberArkToken
    }

    $AddResult = Invoke-RestMethod `
        -Uri $AddAccountUrl `
        -Method Post `
        -Headers $Headers `
        -ContentType "application/json" `
        -Body $AccountPayload

    Write-Host "Account successfully onboarded into CyberArk."
    Write-Host "Returned account ID: $($AddResult.id)"
    Write-Host "Returned account name: $($AddResult.name)"
    Write-Host "Returned userName: $($AddResult.userName)"
    Write-Host "Returned address: $($AddResult.address)"
}
catch {
    Write-Error "Failed to add account to CyberArk. Error: $($_.Exception.Message)"
    Write-Host "Payload used:"
    Write-Host $AccountPayload
}
finally {
    # -----------------------------
    # SECTION 7 - LOG OFF
    # -----------------------------
    # In a real script, call the CyberArk logoff endpoint here if used in your environment.
    # Example endpoint often resembles:
    #   POST /PasswordVault/API/Auth/Logoff
    #
    # Not all environments/documentation examples are identical, so validate locally.
}