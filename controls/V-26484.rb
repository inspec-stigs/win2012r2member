# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26484 - The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.'
control 'V-26484' do
  impact 0.5
  title 'The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  The "Deny log on as a service" user right defines accounts that are denied log on as a service.    In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.  Incorrect configurations could prevent services from starting and result in a DoS.'
  tag 'stig', 'V-26484'
  tag severity: 'medium'
  tag checkid: 'C-46808r1_chk'
  tag fixid: 'F-44654r1_fix'
  tag version: 'WN12-UR-000019-MS'
  tag ruleid: 'SV-51504r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a service" to include the following for domain-joined systems:

Enterprise Admins Group
Domain Admins Group

Configure the "Deny log on as a service" for nondomain systems to include no entries (blank).'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a service" user right on domain-joined systems, this is a finding:

Enterprise Admins Group
Domain Admins Group

If any accounts or groups are defined for the "Deny log on as a service" user right on non-domain-joined systems, this is a finding.'

# START_DESCRIBE V-26484
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26484

end

