# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15666 - Windows Peer-to-Peer networking services must be turned off.'
control 'V-15666' do
  impact 0.5
  title 'Windows Peer-to-Peer networking services must be turned off.'
  desc 'Peer-to-Peer applications can allow unauthorized access to a system and exposure of sensitive data.  This setting will turn off the Microsoft Peer-to-Peer Networking Service.'
  tag 'stig', 'V-15666'
  tag severity: 'medium'
  tag checkid: 'C-47319r2_chk'
  tag fixid: 'F-45939r1_fix'
  tag version: 'WN12-CC-000003'
  tag ruleid: 'SV-53012r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services -> "Turn off Microsoft Peer-to-Peer Networking Services" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Peernet\

Value Name: Disabled

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15666
  
    describe registry_key({
      name: 'Disabled',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Peernet',
    }) do
      its("Disabled") { should eq 1 }
    end

# STOP_DESCRIBE V-15666

end

