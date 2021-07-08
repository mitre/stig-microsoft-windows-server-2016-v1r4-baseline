control 'V-73759' do
  title "The Deny access to this computer from the network user right on member
  servers must be configured to prevent access from highly privileged domain
  accounts and local accounts on domain systems, and from unauthenticated access
  on all systems."
  desc "Inappropriate granting of user rights can provide system,
  administrative, and other high-level capabilities.

    The Deny access to this computer from the network user right defines
  the accounts that are prevented from logging on from the network.

    In an Active Directory Domain, denying logons to the Enterprise Admins and
  Domain Admins groups on lower-trust systems helps mitigate the risk of
  privilege escalation from credential theft attacks, which could lead to the
  compromise of an entire domain.

    Local accounts on domain-joined systems must also be assigned this right to
  decrease the risk of lateral movement resulting from credential theft attacks.

    The Guests group must be assigned this right to prevent unauthenticated
  access.
  "
  impact 0.5
  tag "gtitle": 'SRG-OS-000080-GPOS-00048'
  tag "gid": 'V-73759'
  tag "rid": 'SV-88423r1_rule'
  tag "stig_id": 'WN16-MS-000370'
  tag "fix_id": 'F-80209r1_fix'
  tag "cci": ['CCI-000213']
  tag "nist": ['AC-3', 'Rev_4']
  tag "documentable": false
  desc "check", "This applies to member servers and standalone systems. A
  separate version applies to domain controllers.

  Verify the effective setting in Local Group Policy Editor.

  Run gpedit.msc.

  Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
  >> Security Settings >> Local Policies >> User Rights Assignment.

  If the following accounts or groups are not defined for the Deny access to
  this computer from the network user right, this is a finding.

  Domain Systems Only:
  - Enterprise Admins group
  - Domain Admins group
  - Local account and member of Administrators group or Local account
  (see Note below)

  All Systems:
  - Guests group

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: These are built-in security groups. Local account is more restrictive
  but may cause issues on servers such as systems that provide failover
  clustering."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
  Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
  Deny access to this computer from the network to include the following:

  Domain Systems Only:
  - Enterprise Admins group (SID* S-1-5-21-root domain-519)
  - Domain Admins group (SID* S-1-5-21-domain-512)
  - Local account (SID* S-1-2-0) and member of Administrators group (SID S-1-5-32-544) or Local account
  (see Note below)

  All Systems:
  - Guests group (SID* S-1-5-32-546)

  * See SIDs in https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows

  Systems dedicated to the management of Active Directory (AD admin platforms,
  see V-36436 in the Active Directory Domain STIG) are exempt from denying the
  Enterprise Admins and Domain Admins groups.

  Note: These are built-in security groups. Local account is more restrictive
  but may cause issues on servers such as systems that provide failover
  clustering."
  is_AD_only_system = input('is_AD_only_system')
  domain_role = command('wmic computersystem get domainrole | Findstr /v DomainRole').stdout.strip
  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if !(domain_role == '4') && !(domain_role == '5')
    if is_domain == 'WORKGROUP'
      describe.one do
        describe security_policy do
          its('SeDenyNetworkLogonRight') { should eq ['S-1-5-32-546'] }
        end
        describe security_policy do
          its('SeDenyNetworkLogonRight') { should eq [] }
        end
      end
    else
      if is_AD_only_system
        impact 0.0
        desc 'This system is dedicated to the management of Active Directory, therefore this system is exempt from this control'
        describe 'This system is dedicated to the management of Active Directory, therefore this system is exempt from this control' do
          skip 'This system is dedicated to the management of Active Directory, therefore this system is exempt from this control'
        end
      else
        domain_admin_sid_query = <<-EOH
          $group = New-Object System.Security.Principal.NTAccount('Domain Admins')
          $sid = $group.Translate([security.principal.securityidentifier]).value
          $sid | ConvertTo-Json
        EOH
        domain_admin_sid = json(command: domain_admin_sid_query).params
        
        enterprise_admin_sid_query = <<-EOH
          $group = New-Object System.Security.Principal.NTAccount('Enterprise Admins')
          $sid = $group.Translate([security.principal.securityidentifier]).value
          $sid | ConvertTo-Json
        EOH
        enterprise_admin_sid = json(command: enterprise_admin_sid_query).params
 
        describe security_policy do
          its('SeDenyNetworkLogonRight') { should include "#{domain_admin_sid}" }
        end
        describe security_policy do
          its('SeDenyNetworkLogonRight') { should include "#{enterprise_admin_sid}" }
        end
      end

  if domain_role == '4' || domain_role == '5'
    impact 0.0
    desc 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems'
    describe 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems' do
      skip 'This system is a domain controller, therefore this control is not applicable as it only applies to member servers and standalone systems'
    end
  end
end
