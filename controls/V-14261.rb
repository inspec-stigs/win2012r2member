# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14261 - Windows must be prevented from using Windows Update to search for drivers.'
control 'V-14261' do
  impact 0.5
  title 'Windows must be prevented from using Windows Update to search for drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents Windows from searching Windows Update for device drivers when no local drivers for a device are present.'
  tag 'stig', 'V-14261'
  tag severity: 'medium'
  tag checkid: 'C-47307r2_chk'
  tag fixid: 'F-45927r1_fix'
  tag version: 'WN12-CC-000047'
  tag ruleid: 'SV-53000r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Windows Update device driver searching" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DriverSearching\

Value Name: DontSearchWindowsUpdate

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14261
  
    describe registry_key({
      name: 'DontSearchWindowsUpdate',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DriverSearching',
    }) do
      its("DontSearchWindowsUpdate") { should eq 1 }
    end

# STOP_DESCRIBE V-14261

end

