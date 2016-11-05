# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4446 - Software certificate restriction policies must be enforced.'
control 'V-4446' do
  impact 0.5
  title 'Software certificate restriction policies must be enforced.'
  desc 'Software restriction policies help to protect users and computers from executing unauthorized code such as viruses and Trojans horses.  This setting must be enabled to enforce certificate rules in software restriction policies.'
  tag 'stig', 'V-4446'
  tag severity: 'medium'
  tag checkid: 'C-46965r1_chk'
  tag fixid: 'F-45239r1_fix'
  tag version: 'WN12-SO-000087'
  tag ruleid: 'SV-52221r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\

Value Name: AuthenticodeEnabled

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-4446
  
    describe registry_key({
      name: 'AuthenticodeEnabled',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers',
    }) do
      its("AuthenticodeEnabled") { should eq 1 }
    end

# STOP_DESCRIBE V-4446

end

