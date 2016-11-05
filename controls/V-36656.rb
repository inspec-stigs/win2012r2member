# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36656 - A screen saver must be enabled on the system.'
control 'V-36656' do
  impact 0.5
  title 'A screen saver must be enabled on the system.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  tag 'stig', 'V-36656'
  tag severity: 'medium'
  tag checkid: 'C-46887r2_chk'
  tag fixid: 'F-44833r2_fix'
  tag version: 'WN12-UC-000001'
  tag ruleid: 'SV-51758r2_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Enable screen saver" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\Windows\Control Panel\Desktop\

Value Name: ScreenSaveActive

Type: REG_SZ
Value: 1

Applications requiring continuous, real-time screen display (e.g., network management products) require the following and must be documented with the ISSO:
 
-The logon session does not have administrator rights. 
-The display station (e.g., keyboard, monitor, etc.) is located in a controlled access area.'

# START_DESCRIBE V-36656
  
    describe registry_key({
      name: 'ScreenSaveActive',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Policies\Microsoft\Windows\Control Panel\Desktop',
    }) do
      its("ScreenSaveActive") { should eq 1 }
    end

# STOP_DESCRIBE V-36656

end

