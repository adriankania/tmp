# Check-TlsOnly.ps1
# Audyt ustawień TLS/SSL w Windows Server 2019 (Schannel)

$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$protocols = 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3'
$roles = 'Server','Client'

function Get-SchUseState {
  param([string]$Proto, [string]$Role)

  $path = Join-Path $base "$Proto\$Role"
  $enabled = $null
  $disabledByDefault = $null

  if (Test-Path $path) {
    $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    $enabled = $props.Enabled
    $disabledByDefault = $props.DisabledByDefault
  }

  $state =
    if ($enabled -eq 1) { 'Enabled' }
    elseif ($enabled -eq 0 -or $disabledByDefault -eq 1) { 'Disabled' }
    else { 'OS default' }

  [pscustomobject]@{
    Protocol          = $Proto
    Role              = $Role
    RegistryPath      = if (Test-Path $path) { $path } else { "$path (missing)" }
    Enabled           = $enabled
    DisabledByDefault = $disabledByDefault
    EffectiveState    = $state
  }
}

$report = foreach ($proto in $protocols) {
  foreach ($role in $roles) {
    Get-SchUseState -Proto $proto -Role $role
  }
}

$report | Sort-Object Protocol,Role | Format-Table Protocol,Role,EffectiveState,Enabled,DisabledByDefault -AutoSize