# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36687 - App notifications on the lock screen must be turned off.'
control 'V-36687' do
  impact 0.5
  title 'App notifications on the lock screen must be turned off.'
  desc 'App notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  tag 'stig', 'V-36687'
  tag severity: 'medium'
  tag checkid: 'C-46863r1_chk'
  tag fixid: 'F-44733r1_fix'
  tag version: 'WN12-CC-000052'
  tag ruleid: 'SV-51612r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Turn off app notifications on the lock screen" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\System\

Value Name: DisableLockScreenAppNotifications

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36687
  
    describe registry_key({
      name: 'DisableLockScreenAppNotifications',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\System',
    }) do
      its("DisableLockScreenAppNotifications") { should eq 1 }
    end

# STOP_DESCRIBE V-36687

end

