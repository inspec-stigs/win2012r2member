# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26070 - Standard user accounts must only have Read permissions to the Winlogon registry key.'
control 'V-26070' do
  impact 1.0
  title 'Standard user accounts must only have Read permissions to the Winlogon registry key.'
  desc 'Permissions on the Winlogon registry key must only allow privileged accounts to change registry values.  If standard users have these permissions, there is a potential for programs to run with elevated privileges when a privileged user logs on to the system.'
  tag 'stig', 'V-26070'
  tag severity: 'high'
  tag checkid: 'C-66341r1_chk'
  tag fixid: 'F-71729r1_fix'
  tag version: 'WN12-RG-000001'
  tag ruleid: 'SV-53123r3_rule'
  tag fixtext: 'Maintain the default permissions of the following registry key:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\

TrustedInstaller - Full Control
SYSTEM - Full Control
Administrators - Full Control
Users - Read
ALL APPLICATION PACKAGES - Read'
  tag checktext: 'Run "Regedit".
Navigate to the following registry key:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\

Review the permissions.

If the default permissions listed below have been changed, this is a finding.

TrustedInstaller - Full Control
SYSTEM - Full Control
Administrators - Full Control
Users - Read
ALL APPLICATION PACKAGES - Read'

# START_DESCRIBE V-26070
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26070

end

