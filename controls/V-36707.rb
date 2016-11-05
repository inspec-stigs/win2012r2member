# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36707 - The Windows SmartScreen must be turned off.'
control 'V-36707' do
  impact 0.1
  title 'The Windows SmartScreen must be turned off.'
  desc 'Some features may send system information to the vendor.  Turning off this feature will prevent potentially sensitive information from being sent outside the enterprise.'
  tag 'stig', 'V-36707'
  tag severity: 'low'
  tag checkid: 'C-46876r1_chk'
  tag fixid: 'F-44822r1_fix'
  tag version: 'WN12-CC-000088'
  tag ruleid: 'SV-51747r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Configure Windows SmartScreen" to "Enabled" with "Turn off SmartScreen" selected.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\System\

Value Name: EnableSmartScreen

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36707
  
    describe registry_key({
      name: 'EnableSmartScreen',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\System',
    }) do
      its("EnableSmartScreen") { should eq 0 }
    end

# STOP_DESCRIBE V-36707

end

