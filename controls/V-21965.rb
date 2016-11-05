# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21965 - Device driver searches using Windows Update must be prevented.'
control 'V-21965' do
  impact 0.1
  title 'Device driver searches using Windows Update must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting will prevent the system from searching Windows Update for device drivers.'
  tag 'stig', 'V-21965'
  tag severity: 'low'
  tag checkid: 'C-47492r1_chk'
  tag fixid: 'F-46112r1_fix'
  tag version: 'WN12-CC-000024'
  tag ruleid: 'SV-53186r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Specify search order for device driver source locations" to "Enabled: Do not search Windows Update".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \Software\Policies\Microsoft\Windows\DriverSearching\

Value Name: SearchOrderConfig

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-21965
  
    describe registry_key({
      name: 'SearchOrderConfig',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DriverSearching',
    }) do
      its("SearchOrderConfig") { should eq 0 }
    end

# STOP_DESCRIBE V-21965

end

