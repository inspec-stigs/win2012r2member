# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36684 - Local users on domain-joined computers must not be enumerated.'
control 'V-36684' do
  impact 0.5
  title 'Local users on domain-joined computers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system.  Preventing the enumeration of users limits this information to authorized personnel.'
  tag 'stig', 'V-36684'
  tag severity: 'medium'
  tag checkid: 'C-46862r1_chk'
  tag fixid: 'F-44732r1_fix'
  tag version: 'WN12-CC-000051'
  tag ruleid: 'SV-51611r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Enumerate local users on domain-joined computers" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\System\

Value Name: EnumerateLocalUsers

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36684
  
    describe registry_key({
      name: 'EnumerateLocalUsers',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\System',
    }) do
      its("EnumerateLocalUsers") { should eq 0 }
    end

# STOP_DESCRIBE V-36684

end

