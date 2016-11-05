# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36774 - A screen saver must be defined.'
control 'V-36774' do
  impact 0.1
  title 'A screen saver must be defined.'
  desc 'Unattended systems are susceptible to unauthorized use and must be locked.  Specifying a screen saver ensures the screen saver timeout lock is initiated properly.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  tag 'stig', 'V-36774'
  tag severity: 'low'
  tag checkid: 'C-46888r1_chk'
  tag fixid: 'F-44834r1_fix'
  tag version: 'WN12-UC-000002'
  tag ruleid: 'SV-51759r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Force specific screen saver" to "Enabled" with "scrnsave.scr" specified as the screen saver executable name.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\Windows\Control Panel\Desktop\

Value Name: SCRNSAVE.EXE

Type: REG_SZ
Value: scrnsave.scr'

# START_DESCRIBE V-36774
  
    describe registry_key({
      name: 'SCRNSAVE.EXE',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Policies\Microsoft\Windows\Control Panel\Desktop',
    }) do
      its("SCRNSAVE.EXE") { should eq scrnsave.scr }
    end

# STOP_DESCRIBE V-36774

end

