# Run as admin
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

# Ensure chocolatey installed
if ([bool](Get-Command -Name 'choco' -ErrorAction SilentlyContinue)) {
    Write-Verbose "Chocolatey is already installed, skip installation." -Verbose
}
else {
    Write-Verbose "Installing Chocolatey..." -Verbose
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Ensure OpenSSH Server installed
if ([bool](Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    Write-Verbose "OpenSSH is already installed, skip installation." -Verbose
}
else {
    Write-Verbose "Installing OpenSSH..." -Verbose
    $openSSHpackages = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -ExpandProperty Name

    foreach ($package in $openSSHpackages) {
        Add-WindowsCapability -Online -Name $package
    }

    # Start the sshd service
    Write-Verbose "Starting OpenSSH service..." -Verbose
    Start-Service sshd
    Set-Service -Name sshd -StartupType 'Manual'

    # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
    Write-Verbose "Confirm the Firewall rule is configured..." -Verbose
    if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
        Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
        New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
    }
    else {
        Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
    }
}

# Install Ubuntu WSL2
wsl --install -d Ubuntu-20.04

# Install ansible
bash -c "sudo apt update && sudo apt upgrade -y && sudo apt install -y software-properties-common && sudo apt-add-repository -y ppa:ansible/ansible && sudo apt update && sudo apt -y install ansible git"

# ssh-keygen -t ed25519 -N " " -f C:\Users\$env:UserName\.ssh\id_ed25519
bash -c 'sudo apt install -y ssh && ssh-keygen -t ed25519 -N \"\" -f ~/.ssh/id_ed25519 <<< y'

# Configure public key
$linux_sshuserpath = "/mnt/c/Users/" + ($env:UserName -Replace('\n','')) + "/AppData/Local/Temp/authorized_keys"
$win_sshuserpath = "C:\Users\" + ($env:UserName -Replace('\n','')) + "\AppData\Local\Temp\authorized_keys"
$win_sshuserpathadmin = "C:\ProgramData\ssh\administrators_authorized_keys"
$bashcmd = "sudo cat ~/.ssh/id_ed25519.pub > " + $linux_sshuserpath

bash -c $bashcmd

# https://github.com/PowerShell/Win32-OpenSSH/issues/1306#issuecomment-507311435
rm $win_sshuserpathadmin

New-Item -Type File -Path C:\ProgramData\ssh\administrators_authorized_keys

$public_key=cat $win_sshuserpath

Add-Content $win_sshuserpathadmin $public_key

# Set file permissions
# get-acl C:\ProgramData\ssh\ssh_host_dsa_key | set-acl C:\ProgramData\ssh\administrators_authorized_keys
$acl = Get-Acl C:\ProgramData\ssh\administrators_authorized_keys
$acl.SetAccessRuleProtection($true, $false)
#$administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
$systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
$acl.SetAccessRule($administratorsRule)
$acl.SetAccessRule($systemRule)
$acl | Set-Acl

rm "C:\ProgramData\ssh\sshd_config"

cp ".\sshd_config" "C:\ProgramData\ssh\sshd_config"

# Detect host IP and put it in inventory
$ipv4_addr=(Get-NetIPAddress | Where-Object {$_.AddressFamily -eq 'IPv4'}).IPAddress | findstr /i "192.168.1"

rm inventory

$ansible_user = "ansible_user=" + ($env:UserName -Replace('\n',''))

Add-Content "inventory" "[win]"
Add-Content "inventory" $ipv4_addr
Add-Content "inventory" ""
Add-Content "inventory" "[win:vars]"
Add-Content "inventory" "ansible_connection=ssh"
Add-Content "inventory" "ansible_shell_type=cmd"
Add-Content "inventory" $ansible_user

Stop-Service "sshd" -PassThru
Start-Service "sshd" -PassThru

Write-Host -NoNewLine 'Done! Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
