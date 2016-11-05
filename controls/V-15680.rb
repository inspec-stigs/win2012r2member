# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15680 - The classic logon screen must be required for user logons.'
control 'V-15680' do
  impact 0.1
  title 'The classic logon screen must be required for user logons.'
  desc 'The classic logon screen requires users to enter a logon name and password to access a system.  The simple logon screen or Welcome screen displays  usernames for selection, providing part of the necessary logon information.'
  tag 'stig', 'V-15680'
  tag severity: 'low'
  tag checkid: 'C-61741r2_chk'
  tag fixid: 'F-66505r3_fix'
  tag version: 'WN12-CC-000049-MS'
  tag ruleid: 'SV-53036r2_rule'
  tag fixtext: 'If the system is a member of a domain, this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Always use classic logon" to "Enabled".'
  tag checktext: 'If the system is a member of a domain, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name:  LogonType

Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-15680
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15680

end

