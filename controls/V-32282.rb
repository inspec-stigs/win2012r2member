# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-32282 - Standard user accounts must only have Read permissions to the Active Setup\Installed Components registry key.'
control 'V-32282' do
  impact 1.0
  title 'Standard user accounts must only have Read permissions to the Active Setup\Installed Components registry key.'
  desc 'Permissions on the Active Setup\Installed Components registry key must only allow privileged accounts to add or change registry values.  If standard user accounts have these permissions, there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  tag 'stig', 'V-32282'
  tag severity: 'high'
  tag checkid: 'C-66343r1_chk'
  tag fixid: 'F-71731r1_fix'
  tag version: 'WN12-RG-000002'
  tag ruleid: 'SV-52956r3_rule'
  tag fixtext: 'Maintain the default permissions of the following registry keys:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\ (64-bit systems only)
 
Users - Read
Administrators - Full Control
SYSTEM - Full Control
CREATOR OWNER - Full Control (Subkeys only)
ALL APPLICATION PACKAGES - Read'
  tag checktext: 'Run "Regedit".
Navigate to the following registry keys and review the permissions:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Active Setup\Installed Components\
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components\ (64-bit systems)

If the default permissions listed below have been changed, this is a finding.

Users - Read
Administrators - Full Control
SYSTEM - Full Control
CREATOR OWNER - Full Control (Subkeys only)
ALL APPLICATION PACKAGES - Read'

# START_DESCRIBE V-32282
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-32282

end

