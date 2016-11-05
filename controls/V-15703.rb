# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15703 - Users must not be prompted to search Windows Update for device drivers.'
control 'V-15703' do
  impact 0.1
  title 'Users must not be prompted to search Windows Update for device drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents users from being prompted to search Windows Update for device drivers.'
  tag 'stig', 'V-15703'
  tag severity: 'low'
  tag checkid: 'C-47421r2_chk'
  tag fixid: 'F-46041r1_fix'
  tag version: 'WN12-CC-000026'
  tag ruleid: 'SV-53115r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Driver Installation -> "Turn off Windows Update device driver search prompt" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DriverSearching\

Value Name: DontPromptForWindowsUpdate

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15703
  
    describe registry_key({
      name: 'DontPromptForWindowsUpdate',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DriverSearching',
    }) do
      its("DontPromptForWindowsUpdate") { should eq 1 }
    end

# STOP_DESCRIBE V-15703

end

