# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15683 - File Explorer shell protocol must run in protected mode.'
control 'V-15683' do
  impact 0.5
  title 'File Explorer shell protocol must run in protected mode.'
  desc 'The shell protocol will  limit the set of folders applications can open when run in protected mode.  Restricting files an application can open to a limited set of folders increases the security of Windows.'
  tag 'stig', 'V-15683'
  tag severity: 'medium'
  tag checkid: 'C-47350r2_chk'
  tag fixid: 'F-45971r1_fix'
  tag version: 'WN12-CC-000091'
  tag ruleid: 'SV-53045r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off shell protocol protected mode" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: PreXPSP2ShellProtocolBehavior

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15683
  
    describe registry_key({
      name: 'PreXPSP2ShellProtocolBehavior',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    }) do
      its("PreXPSP2ShellProtocolBehavior") { should eq 0 }
    end

# STOP_DESCRIBE V-15683

end

