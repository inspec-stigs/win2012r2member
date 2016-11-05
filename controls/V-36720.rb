# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36720 - The Windows Remote Management (WinRM) service must not store RunAs credentials.'
control 'V-36720' do
  impact 0.5
  title 'The Windows Remote Management (WinRM) service must not store RunAs credentials.'
  desc 'Storage of administrative credentials could allow unauthorized access.  Disallowing the storage of RunAs credentials for Windows Remote Management will prevent them from being used with plug-ins.'
  tag 'stig', 'V-36720'
  tag severity: 'medium'
  tag checkid: 'C-46886r1_chk'
  tag fixid: 'F-44832r1_fix'
  tag version: 'WN12-CC-000128'
  tag ruleid: 'SV-51757r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Disallow WinRM from storing RunAs credentials" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WinRM\Service\

Value Name: DisableRunAs

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36720
  
    describe registry_key({
      name: 'DisableRunAs',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\WinRM\Service',
    }) do
      its("DisableRunAs") { should eq 1 }
    end

# STOP_DESCRIBE V-36720

end

