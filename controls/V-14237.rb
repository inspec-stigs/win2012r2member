# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14237 - User Account Control must be configured to detect application installations and prompt for elevation.'
control 'V-14237' do
  impact 0.5
  title 'User Account Control must be configured to detect application installations and prompt for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting requires Windows to respond to application installation requests by prompting for credentials.'
  tag 'stig', 'V-14237'
  tag severity: 'medium'
  tag checkid: 'C-47255r2_chk'
  tag fixid: 'F-45875r2_fix'
  tag version: 'WN12-SO-000080'
  tag ruleid: 'SV-52949r1_rule'
  tag fixtext: 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Detect application installations and prompt for elevation" to "Enabled".'
  tag checktext: 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableInstallerDetection

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14237
  
    describe registry_key({
      name: 'EnableInstallerDetection',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("EnableInstallerDetection") { should eq 1 }
    end

# STOP_DESCRIBE V-14237

end

