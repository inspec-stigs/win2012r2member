# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36775 - Changing the screen saver must be prevented.'
control 'V-36775' do
  impact 0.1
  title 'Changing the screen saver must be prevented.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Preventing users from changing the screen saver ensures an approved screen saver is used.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  tag 'stig', 'V-36775'
  tag severity: 'low'
  tag checkid: 'C-46890r1_chk'
  tag fixid: 'F-44836r1_fix'
  tag version: 'WN12-UC-000004'
  tag ruleid: 'SV-51761r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Prevent changing screen saver" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: NoDispScrSavPage

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36775
  
    describe registry_key({
      name: 'NoDispScrSavPage',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("NoDispScrSavPage") { should eq 1 }
    end

# STOP_DESCRIBE V-36775

end

