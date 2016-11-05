# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36776 - Notifications from Windows Push Network Service must be turned off.'
control 'V-36776' do
  impact 0.1
  title 'Notifications from Windows Push Network Service must be turned off.'
  desc 'The Windows Push Notification Service (WNS) allows third-party vendors to send updates for toasts, tiles, and badges.'
  tag 'stig', 'V-36776'
  tag severity: 'low'
  tag checkid: 'C-46891r1_chk'
  tag fixid: 'F-44837r1_fix'
  tag version: 'WN12-UC-000005'
  tag ruleid: 'SV-51762r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Start Menu and Taskbar -> Notifications -> "Turn off notifications network usage" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\

Value Name: NoCloudApplicationNotification

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36776
  
    describe registry_key({
      name: 'NoCloudApplicationNotification',
      hive: 'HKEY_CURRENT_USER',
      key:  'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications',
    }) do
      its("NoCloudApplicationNotification") { should eq 1 }
    end

# STOP_DESCRIBE V-36776

end

