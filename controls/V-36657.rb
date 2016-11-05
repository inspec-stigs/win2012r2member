# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36657 - The screen saver must be password protected.'
control 'V-36657' do
  impact 0.5
  title 'The screen saver must be password protected.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked when unattended.  Enabling a password-protected screen saver to engage after a specified period of time helps protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  tag 'stig', 'V-36657'
  tag severity: 'medium'
  tag checkid: 'C-46889r1_chk'
  tag fixid: 'F-44835r1_fix'
  tag version: 'WN12-UC-000003'
  tag ruleid: 'SV-51760r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Password protect the screen saver" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\Windows\Control Panel\Desktop\

Value Name: ScreenSaverIsSecure

Type: REG_SZ
Value: 1'

# START_DESCRIBE V-36657
  
    describe registry_key({
      name: 'ScreenSaverIsSecure',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Policies\Microsoft\Windows\Control Panel\Desktop',
    }) do
      its("ScreenSaverIsSecure") { should eq 1 }
    end

# STOP_DESCRIBE V-36657

end

