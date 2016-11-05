# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21969 - Access to Windows Online Troubleshooting Service (WOTS) must be prevented.'
control 'V-21969' do
  impact 0.1
  title 'Access to Windows Online Troubleshooting Service (WOTS) must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents users from searching troubleshooting content on Microsoft servers.  Only local content will be available.'
  tag 'stig', 'V-21969'
  tag severity: 'low'
  tag checkid: 'C-47494r1_chk'
  tag fixid: 'F-46114r2_fix'
  tag version: 'WN12-CC-000067'
  tag ruleid: 'SV-53188r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Scripted Diagnostics -> "Troubleshooting: Allow users to access online troubleshooting content on Microsoft servers from the Troubleshooting Control Panel (via the Windows Online Troubleshooting Service - WOTS)" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\

Value Name: EnableQueryRemoteServer

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-21969
  
    describe registry_key({
      name: 'EnableQueryRemoteServer',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy',
    }) do
      its("EnableQueryRemoteServer") { should eq 0 }
    end

# STOP_DESCRIBE V-21969

end

