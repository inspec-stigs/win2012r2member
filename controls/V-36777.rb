# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36777 - Toast notifications to the lock screen must be turned off.'
control 'V-36777' do
  impact 0.1
  title 'Toast notifications to the lock screen must be turned off.'
  desc 'Toast notifications that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  tag 'stig', 'V-36777'
  tag severity: 'low'
  tag checkid: 'C-46892r1_chk'
  tag fixid: 'F-44838r1_fix'
  tag version: 'WN12-UC-000006'
  tag ruleid: 'SV-51763r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications -> "Turn off toast notifications on the lock screen" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\

Value Name: NoToastApplicationNotificationOnLockScreen

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36777
  
    describe registry_key({
      name: 'NoToastApplicationNotificationOnLockScreen',
      hive: 'HKEY_CURRENT_USER',
      key:  'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications',
    }) do
      its("NoToastApplicationNotificationOnLockScreen") { should eq 1 }
    end

# STOP_DESCRIBE V-36777

end

