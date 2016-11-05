# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26473 - The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group and other approved groups.'
control 'V-26473' do
  impact 0.5
  title 'The Allow log on through Remote Desktop Services user right must only be assigned to the Administrators group and other approved groups.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Allow log on through Remote Desktop Services" user right can access a system through Remote Desktop.'
  tag 'stig', 'V-26473'
  tag severity: 'medium'
  tag checkid: 'C-69293r1_chk'
  tag fixid: 'F-74893r1_fix'
  tag version: 'WN12-UR-000006-MS'
  tag ruleid: 'SV-83319r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on through Remote Desktop Services" to only include the following accounts or groups:

Administrators   

If the system serves the Remote Desktop Services role, the Remote Desktop Users group or another more restrictive group may be included.  

Organizations may grant this to other groups, such as more restrictive groups with administrative or management functions, if required.  Remote Desktop Services access must be restricted to the accounts that require it.  This must be documented with the ISSO.'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Allow log on through Remote Desktop Services" user right, this is a finding:

Administrators

If the system serves the Remote Desktop Services role, the Remote Desktop Users group or another more restrictive group may be included.  

Organizations may grant this to other groups, such as more restrictive groups with administrative or management functions, if required.  Remote Desktop Services access must be restricted to the accounts that require it.  This must be documented with the ISSO.'

# START_DESCRIBE V-26473
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26473

end

