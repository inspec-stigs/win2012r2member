# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3454 - Remote Desktop Services must be configured with the client connection encryption set to the required level.'
control 'V-3454' do
  impact 0.5
  title 'Remote Desktop Services must be configured with the client connection encryption set to the required level.'
  desc 'Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High Level" will ensure encryption of Remote Desktop Services sessions in both directions.'
  tag 'stig', 'V-3454'
  tag severity: 'medium'
  tag checkid: 'C-47216r2_chk'
  tag fixid: 'F-45825r1_fix'
  tag version: 'WN12-CC-000100'
  tag ruleid: 'SV-52899r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Security -> "Set client connection encryption level" to "Enabled" and "High Level".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MinEncryptionLevel

Type: REG_DWORD
Value: 3'

# START_DESCRIBE V-3454
  
    describe registry_key({
      name: 'MinEncryptionLevel',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("MinEncryptionLevel") { should eq 3 }
    end

# STOP_DESCRIBE V-3454

end

