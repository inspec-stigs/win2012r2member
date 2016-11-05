# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-34974 - The Windows Installer Always install with elevated privileges option must be disabled.'
control 'V-34974' do
  impact 1.0
  title 'The Windows Installer Always install with elevated privileges option must be disabled.'
  desc 'Standard user accounts must not be granted elevated privileges.  Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.'
  tag 'stig', 'V-34974'
  tag severity: 'high'
  tag checkid: 'C-47260r1_chk'
  tag fixid: 'F-45880r1_fix'
  tag version: 'WN12-CC-000116'
  tag ruleid: 'SV-52954r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Always install with elevated privileges" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: AlwaysInstallElevated

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-34974
  
    describe registry_key({
      name: 'AlwaysInstallElevated',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Installer',
    }) do
      its("AlwaysInstallElevated") { should eq 0 }
    end

# STOP_DESCRIBE V-34974

end

