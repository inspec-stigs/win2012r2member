# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-16008 - Windows must elevate all applications in User Account Control, not just signed ones.'
control 'V-16008' do
  impact 0.5
  title 'Windows must elevate all applications in User Account Control, not just signed ones.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures whether Windows elevates all applications, or only signed ones.'
  tag 'stig', 'V-16008'
  tag severity: 'medium'
  tag checkid: 'C-47448r1_chk'
  tag fixid: 'F-46068r2_fix'
  tag version: 'WN12-SO-000081'
  tag ruleid: 'SV-53142r1_rule'
  tag fixtext: 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Only elevate executables that are signed and validated" to "Disabled".'
  tag checktext: 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ValidateAdminCodeSignatures

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-16008
  
    describe registry_key({
      name: 'ValidateAdminCodeSignatures',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("ValidateAdminCodeSignatures") { should eq 0 }
    end

# STOP_DESCRIBE V-16008

end

