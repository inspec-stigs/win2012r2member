# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15718 - Turning off File Explorer heap termination on corruption must be disabled.'
control 'V-15718' do
  impact 0.1
  title 'Turning off File Explorer heap termination on corruption must be disabled.'
  desc 'Legacy plug-in applications may continue to function when a File Explorer session has become corrupt.  Disabling this feature will prevent this.'
  tag 'stig', 'V-15718'
  tag severity: 'low'
  tag checkid: 'C-47443r1_chk'
  tag fixid: 'F-46063r1_fix'
  tag version: 'WN12-CC-000090'
  tag ruleid: 'SV-53137r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off heap termination on corruption" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Explorer\

Value Name: NoHeapTerminationOnCorruption

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15718
  
    describe registry_key({
      name: 'NoHeapTerminationOnCorruption',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Explorer',
    }) do
      its("NoHeapTerminationOnCorruption") { should eq 0 }
    end

# STOP_DESCRIBE V-15718

end

