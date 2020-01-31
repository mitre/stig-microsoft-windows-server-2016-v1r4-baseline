control 'V-73643' do
  title "Windows Server 2016 must be configured to require a strong session
  key."
  desc "A computer connecting to a domain controller will establish a secure
  channel. The secure channel connection may be subject to compromise, such as
  hijacking or eavesdropping, if strong session keys are not used to establish
  the connection. Requiring strong session keys enforces 128-bit encryption
  between systems.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000423-GPOS-00187'
  tag "satisfies": ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188']
  tag "gid": 'V-73643'
  tag "rid": 'SV-88307r1_rule'
  tag "stig_id": 'WN16-SO-000130'
  tag "fix_id": 'F-80093r1_fix'
  tag "cci": ['CCI-002418', 'CCI-002421']
  tag "nist": ['SC-8', 'SC-8 (1)', 'Rev_4']
  tag "documentable": false
  tag "check": "If the following registry value does not exist or is not
  configured as specified, this is a finding.

  Registry Hive: HKEY_LOCAL_MACHINE
  Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

  Value Name: RequireStrongKey

  Value Type: REG_DWORD
  Value: 0x00000001 (1)

  This setting may prevent a system from being joined to a domain if not
  configured consistently between systems."
  tag "fix": "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> Security Options >> Domain
  member: Require strong (Windows 2000 or Later) session key to Enabled."
  describe registry_key('HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters') do
    it { should have_property 'RequireStrongKey' }
    its('RequireStrongKey') { should cmp 1 }
  end
end
