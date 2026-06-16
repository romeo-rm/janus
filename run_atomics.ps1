Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force

$techniques = @(
    @{id="T1082";     test=1;  name="System Information Discovery"},
    @{id="T1547.001"; test=1;  name="Registry Run Key Persistence"},
    @{id="T1059.001"; test=17; name="PowerShell Execution"},
    @{id="T1069.001"; test=1;  name="Local Groups Discovery"},
    @{id="T1016";     test=1;  name="Network Config Discovery"},
    @{id="T1018";     test=1;  name="Remote System Discovery"},
    @{id="T1083";     test=1;  name="File and Directory Discovery"},
    @{id="T1027";     test=1;  name="Obfuscated Files"},
    @{id="T1112";     test=1;  name="Modify Registry"},
    @{id="T1562.001"; test=1;  name="Disable Security Tools"},
    @{id="T1490";     test=1;  name="Shadow Copy Deletion"},
    @{id="T1486";     test=1;  name="File Encryption"}
)

foreach ($t in $techniques) {
    Write-Host "[*] === $($t.id) - $($t.name) ===" -ForegroundColor Cyan
    try {
        Invoke-AtomicTest $t.id -TestNumbers $t.test -Confirm:$false -TimeoutSeconds 45 2>&1 | Out-String | Write-Host
        Write-Host "[+] $($t.id) executed" -ForegroundColor Green
    } catch {
        Write-Host "[-] $($t.id) failed: $_" -ForegroundColor Red
    }
    Start-Sleep -Seconds 3
}

Write-Host "[*] All atomic tests complete" -ForegroundColor Yellow
