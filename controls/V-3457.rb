# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3457 - Remote Desktop Services must be configured to set a time limit for disconnected sessions.'
control 'V-3457' do
  impact 0.5
  title 'Remote Desktop Services must be configured to set a time limit for disconnected sessions.'
  desc 'This setting controls how long a session will remain open if it is unexpectedly terminated.  Such sessions use system resources and must be terminated as soon as possible.'
  tag 'stig', 'V-3457'
  tag severity: 'medium'
  tag checkid: 'C-47219r2_chk'
  tag fixid: 'F-45828r1_fix'
  tag version: 'WN12-CC-000102'
  tag ruleid: 'SV-52902r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Session Time Limits -> "Set time limit for disconnected sessions" to "Enabled", and "End a disconnected session" to "1 minute".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MaxDisconnectionTime

Type: REG_DWORD
Value: 0x0000ea60 (60000)'

# START_DESCRIBE V-3457
  
    describe registry_key({
      name: 'MaxDisconnectionTime',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("MaxDisconnectionTime") { should eq 0x0000ea60 }
    end

# STOP_DESCRIBE V-3457

end

