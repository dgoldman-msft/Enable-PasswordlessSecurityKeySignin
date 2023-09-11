# Enable-PasswordlessSecurityKeySignin
Enable Passwordless Security Key Signin

## Getting Started with Enable-PasswordlessSecurityKeySignin

This script will request your local active directory as well as your Azure tenant global administrator credentials

### DESCRIPTION

This script will enable passwordless authentication to on-premises resources for environments with both Azure Active Directory (Azure AD)-joined and hybrid Azure AD-joined Windows 10 devices.

### Examples

- EXAMPLE 1: C:\PS> Enable-PasswordlessSecurityKeySignin -UserPrincipalName admin@contoso.onmicrosoft.com

        This will enable passwordless security using MFA authentication