# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21970 - Responsiveness events must be prevented from being aggregated and sent to Microsoft.'
control 'V-21970' do
  impact 0.1
  title 'Responsiveness events must be prevented from being aggregated and sent to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents responsiveness events from being aggregated and sent to Microsoft.'
  tag 'stig', 'V-21970'
  tag severity: 'low'
  tag checkid: 'C-47434r1_chk'
  tag fixid: 'F-46054r1_fix'
  tag version: 'WN12-CC-000068'
  tag ruleid: 'SV-53128r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Windows Performance PerfTrack -> "Enable/Disable PerfTrack" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\

Value Name: ScenarioExecutionEnabled

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-21970
  
    describe registry_key({
      name: 'ScenarioExecutionEnabled',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}',
    }) do
      its("ScenarioExecutionEnabled") { should eq 0 }
    end

# STOP_DESCRIBE V-21970

end

