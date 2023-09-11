function Enable-PasswordlessSecurityKeySignin {
    <#

    .SYNOPSIS
        Enable Passwordless Security Key Signin

    .DESCRIPTION
        Enable passwordless authentication to on-premises resources for environments with both Azure Active Directory (Azure AD)-joined and hybrid Azure AD-joined Windows 10 devices

    .EXAMPLE
        C:\PS> Enable-PasswordlessSecurityKeySignin -UserPrincipalName admin@contoso.onmicrosoft.com

        This will enable passwordless security using MFA authentication

    .NOTES
        https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-authentication-passwordless-security-key-on-premises

        Supported scenarios: The scenario in this article supports SSO in both of the following instances:
            Cloud resources such as Microsoft 365 and other Security Assertion Markup Language (SAML)-enabled applications.
            On-premises resources, and Windows-integrated authentication to websites. The resources can include websites and SharePoint sites that require IIS authentication and/or resources that use NTLM authentication.

        The following scenarios aren't supported:
            Windows Server Active Directory Domain Services (AD DS)-joined (on-premises only devices) deployment.
            Remote Desktop Protocol (RDP), virtual desktop infrastructure (VDI), and Citrix scenarios by using a security key.
            S/MIME by using a security key.
            Run as by using a security key.
            Log in to a server by using a security key.
  #>

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $True, Position = 1, Message = "Global Administrator Account")]
        [string]
        $UserPrincipalName
    )

    begin {
        Write-Output "Starting process!"
        $importModule = $False
        $domain = $env:USERDNSDOMAIN
        $dependencyModule = 'AzureADHybridAuthenticationManagement'

        Write-Output "Verifying TLS 1.2 for PowerShell gallery access"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }

    process {
        try {
            Write-Output "Checking for module $($dependencyModule)"
            if (-NOT (Get-Module -Name $dependencyModule -ListAvailable -ErrorAction Stop)) {
                Write-Output "Module not found. Installing module $($dependencyModule) from the PowerShell Gallery"
                if (-NOT (Install-Module -Name $dependencyModule -AllowClobber -PassThru -ErrorAction Stop)) {
                    Write-Output "ERROR: for $($dependencyModule)"
                    return
                }
                else {
                    $importModule = $True
                }
            }
            else {
                $importModule = $True
            }

            if ($importModule) {
                Import-Module -Name $dependencyModule -ErrorAction Stop
                Write-Output "Module $($dependencyModule) imported!"
            }
            else {
                Write-Output "ERROR: Module $($dependencyModule) not imported"
                return
            }
        }
        catch {
            Throw "ERROR: $_.Exception.Message"
            return
        }

        Write-Output "Creating a Kerberos Server object in $($domain)."
        Write-Output "Enter a domain administrator username and password."
        $domainCred = Get-Credential -Message 'An Active Directory user who is a member of the Domain Admins group.'

        try {
            Write-Output "Create the new Azure AD Kerberos Server object in Active Directory and then publish it to Azure Active Directory."
            if (-NOT (Set-AzureADKerberosServer -Domain $domain -UserPrincipalName $userPrincipalName -DomainCredential $domainCred -ErrorAction Stop -PassThru)) { Write-Output "ERROR: Set-AzureADKerberosServer" }
            else { Write-Output "SUCCESS: Set-AzureADKerberosServer" }
        }
        catch {
            Throw "ERROR: $_.Exception.Message"
            return
        }

        try {
            $answer = Read-Host "Would you like to verify the Azure AD Kerberos Server Object? 1 = Yes, 2 = No"
            switch ($answer) {

                1: {
                    Get-AzureADKerberosServer -Domain $domain -CloudCredential $cloudCred -DomainCredential $domainCred -ErrorAction Stop
                }
                2: {
                    return
                }
            }
        }
        catch {
            Throw "ERROR: $_.Exception.Message"
            return
        }
    }

    end {
        Write-Output "Completed!"
    }
}