# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1127 - Only administrators responsible for the member server must have Administrator rights on the system.'
control 'V-1127' do
  impact 1.0
  title 'Only administrators responsible for the member server must have Administrator rights on the system.'
  desc 'An account that does not have Administrator duties must not have Administrator rights.  Such rights would allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to attack.  System administrators must log on to systems only using accounts with the minimum level of authority necessary.  For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group (see V-36433 in the Active Directory Domain STIG).  Restricting highly privileged accounts from the local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.   Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from this.  AD admin platforms may use the Domain Admins group or a domain administrative group created specifically for AD admin platforms (see V-43711 in the Active Directory Domain STIG).  Standard user accounts must not be members of the built-in Administrators group.'
  tag 'stig', 'V-1127'
  tag severity: 'high'
  tag checkid: 'C-54671r1_chk'
  tag fixid: 'F-58527r1_fix'
  tag version: 'WN12-GE-000004-MS'
  tag ruleid: 'SV-51511r3_rule'
  tag fixtext: 'Configure the system to include only administrator groups or accounts that are responsible for the system in the local Administrators group.

For domain-joined member servers, replace the Domain Admins group with a domain member server administrator group. 

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from this.  AD admin platforms may use the Domain Admins group or a domain administrative group created specifically for AD admin platforms (see V-43711 in the Active Directory Domain STIG).

Remove any standard user accounts.'
  tag checktext: 'Review the local Administrators group.  Only the appropriate administrator groups or accounts responsible for administration of the system may be members of the group.

For domain-joined member servers, the Domain Admins group must be replaced by a domain member server administrator group. 

Systems dedicated to the management of Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG) are exempt from this.  AD admin platforms may use the Domain Admins group or a domain administrative group created specifically for AD admin platforms (see V-43711 in the Active Directory Domain STIG).

Standard user accounts must not be members of the local Administrator group.

If prohibited accounts are members of the local Administrators group, this is a finding.

The built-in Administrator account or other required administrative accounts would not be a finding.'

# START_DESCRIBE V-1127
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1127

end

