# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14242 - User Account Control must virtualize file and registry write failures to per-user locations.'
control 'V-14242' do
  impact 0.5
  title 'User Account Control must virtualize file and registry write failures to per-user locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures non-UAC-compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.'
  tag 'stig', 'V-14242'
  tag severity: 'medium'
  tag checkid: 'C-47259r1_chk'
  tag fixid: 'F-45879r2_fix'
  tag version: 'WN12-SO-000085'
  tag ruleid: 'SV-52953r1_rule'
  tag fixtext: 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled".'
  tag checktext: 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14242
  
    describe registry_key({
      name: 'EnableVirtualization',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("EnableVirtualization") { should eq 1 }
    end

# STOP_DESCRIBE V-14242

end

