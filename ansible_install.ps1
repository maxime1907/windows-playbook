# Install windows-playbook directory
bash -c "rm -rf /tmp/windows-playbook && cp -R . /tmp/windows-playbook"

bash -c 'cd /tmp/windows-playbook && ansible-galaxy install -r requirements.yml && ansible-playbook main.yml'

Write-Host -NoNewLine 'Done! Press any key to continue...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
