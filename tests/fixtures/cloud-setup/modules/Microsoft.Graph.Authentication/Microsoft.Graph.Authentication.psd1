# A stand-in for the Microsoft Graph PowerShell SDK sign-in module, so the
# setup script can run against a recorded tenant. Its version is far above any
# real release, so it wins over an installed copy. It also answers the script's
# Invoke-RestMethod calls to Microsoft's sign-in service.
@{
    RootModule        = 'Microsoft.Graph.Authentication.psm1'
    ModuleVersion     = '99.0.0'
    GUID              = '5b0f6f3e-1f6a-4c55-9a52-3f5e6f2d7a10'
    FunctionsToExport = @('Connect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest', 'Disconnect-MgGraph', 'Invoke-RestMethod')
    CmdletsToExport   = @()
    AliasesToExport   = @()
}
