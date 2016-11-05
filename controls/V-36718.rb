# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36718 - The Windows Remote Management (WinRM) service must not use Basic authentication.'
control 'V-36718' do
  impact 1.0
  title 'The Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  tag 'stig', 'V-36718'
  tag severity: 'high'
  tag checkid: 'C-46884r1_chk'
  tag fixid: 'F-44830r1_fix'
  tag version: 'WN12-CC-000126'
  tag ruleid: 'SV-51755r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Allow Basic authentication" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WinRM\Service\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36718
  
    describe registry_key({
      name: 'AllowBasic',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\WinRM\Service',
    }) do
      its("AllowBasic") { should eq 0 }
    end

# STOP_DESCRIBE V-36718

end

