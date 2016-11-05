# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1145 - Automatic logons must be disabled.'
control 'V-1145' do
  impact 0.5
  title 'Automatic logons must be disabled.'
  desc 'Allowing a system to automatically log on when the machine is booted could give access to any unauthorized individual who restarts the computer.  Automatic logon with administrator privileges would give full access to an unauthorized individual.'
  tag 'stig', 'V-1145'
  tag severity: 'medium'
  tag checkid: 'C-46924r1_chk'
  tag fixid: 'F-45132r1_fix'
  tag version: 'WN12-SO-000036'
  tag ruleid: 'SV-52107r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)" to "Disabled".

Ensure no passwords are stored in the "DefaultPassword" registry value noted below:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: DefaultPassword

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: AutoAdminLogon

Type: REG_SZ
Value: 0'

# START_DESCRIBE V-1145
  
    describe registry_key({
      name: 'AutoAdminLogon',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    }) do
      its("AutoAdminLogon") { should eq 0 }
    end

# STOP_DESCRIBE V-1145

end

