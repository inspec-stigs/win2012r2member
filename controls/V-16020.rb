# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-16020 - The Windows Customer Experience Improvement Program must be disabled.'
control 'V-16020' do
  impact 0.5
  title 'The Windows Customer Experience Improvement Program must be disabled.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting ensures the Windows Customer Experience Improvement Program is disabled so information is not passed to the vendor.'
  tag 'stig', 'V-16020'
  tag severity: 'medium'
  tag checkid: 'C-47449r1_chk'
  tag fixid: 'F-46069r1_fix'
  tag version: 'WN12-CC-000045'
  tag ruleid: 'SV-53143r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> "Turn off Windows Customer Experience Improvement Program" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\SQMClient\Windows\

Value Name: CEIPEnable

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-16020
  
    describe registry_key({
      name: 'CEIPEnable',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\SQMClient\Windows',
    }) do
      its("CEIPEnable") { should eq 0 }
    end

# STOP_DESCRIBE V-16020

end

