# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1159 - The Recovery Console option must be set to prevent automatic logon to the system.'
control 'V-1159' do
  impact 1.0
  title 'The Recovery Console option must be set to prevent automatic logon to the system.'
  desc 'If this option is enabled, the Recovery Console does not require a password and automatically logs on to the system.  This could allow unauthorized administrative access to the system.'
  tag 'stig', 'V-1159'
  tag severity: 'high'
  tag checkid: 'C-47186r2_chk'
  tag fixid: 'F-45795r1_fix'
  tag version: 'WN12-SO-000071'
  tag ruleid: 'SV-52869r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Recovery console: Allow automatic administrative logon" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\

Value Name: SecurityLevel

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-1159
  
    describe registry_key({
      name: 'SecurityLevel',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole',
    }) do
      its("SecurityLevel") { should eq 0 }
    end

# STOP_DESCRIBE V-1159

end

