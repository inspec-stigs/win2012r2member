# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36714 - The Windows Remote Management (WinRM) client must not use Digest authentication.'
control 'V-36714' do
  impact 0.5
  title 'The Windows Remote Management (WinRM) client must not use Digest authentication.'
  desc 'Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks.'
  tag 'stig', 'V-36714'
  tag severity: 'medium'
  tag checkid: 'C-46883r1_chk'
  tag fixid: 'F-44829r1_fix'
  tag version: 'WN12-CC-000125'
  tag ruleid: 'SV-51754r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Disallow Digest authentication" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WinRM\Client\

Value Name: AllowDigest

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36714
  
    describe registry_key({
      name: 'AllowDigest',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\WinRM\Client',
    }) do
      its("AllowDigest") { should eq 0 }
    end

# STOP_DESCRIBE V-36714

end

