# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21963 - Windows Update must be prevented from searching for point and print drivers.'
control 'V-21963' do
  impact 0.1
  title 'Windows Update must be prevented from searching for point and print drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting will prevent Windows from searching Windows Update for point and print drivers.  Only the local driver store and server driver cache will be searched.'
  tag 'stig', 'V-21963'
  tag severity: 'low'
  tag checkid: 'C-47490r1_chk'
  tag fixid: 'F-46110r1_fix'
  tag version: 'WN12-CC-000016'
  tag ruleid: 'SV-53184r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Printers -> "Extend Point and Print connection to search Windows Update" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Printers\

Value Name: DoNotInstallCompatibleDriverFromWindowsUpdate

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-21963
  
    describe registry_key({
      name: 'DoNotInstallCompatibleDriverFromWindowsUpdate',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Printers',
    }) do
      its("DoNotInstallCompatibleDriverFromWindowsUpdate") { should eq 1 }
    end

# STOP_DESCRIBE V-21963

end

