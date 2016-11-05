# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14240 - User Account Control must run all administrators in Admin Approval Mode, enabling UAC.'
control 'V-14240' do
  impact 0.5
  title 'User Account Control must run all administrators in Admin Approval Mode, enabling UAC.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting enables UAC.'
  tag 'stig', 'V-14240'
  tag severity: 'medium'
  tag checkid: 'C-47257r2_chk'
  tag fixid: 'F-45877r2_fix'
  tag version: 'WN12-SO-000083'
  tag ruleid: 'SV-52951r1_rule'
  tag fixtext: 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Run all administrators in Admin Approval Mode" to "Enabled".'
  tag checktext: 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableLUA

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14240
  
    describe registry_key({
      name: 'EnableLUA',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("EnableLUA") { should eq 1 }
    end

# STOP_DESCRIBE V-14240

end

