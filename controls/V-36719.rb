# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36719 - The Windows Remote Management (WinRM) service must not allow unencrypted traffic.'
control 'V-36719' do
  impact 0.5
  title 'The Windows Remote Management (WinRM) service must not allow unencrypted traffic.'
  desc 'Unencrypted remote access to a system can allow sensitive information to be compromised.  Windows remote management connections must be encrypted to prevent this.'
  tag 'stig', 'V-36719'
  tag severity: 'medium'
  tag checkid: 'C-46885r1_chk'
  tag fixid: 'F-44831r1_fix'
  tag version: 'WN12-CC-000127'
  tag ruleid: 'SV-51756r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Allow unencrypted traffic" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WinRM\Service\

Value Name: AllowUnencryptedTraffic

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36719
  
    describe registry_key({
      name: 'AllowUnencryptedTraffic',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\WinRM\Service',
    }) do
      its("AllowUnencryptedTraffic") { should eq 0 }
    end

# STOP_DESCRIBE V-36719

end

