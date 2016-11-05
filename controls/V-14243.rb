# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14243 - The system must require username and password to elevate a running application.'
control 'V-14243' do
  impact 0.5
  title 'The system must require username and password to elevate a running application.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user.  This setting configures the system to always require users to type in a username and password to elevate a running application.'
  tag 'stig', 'V-14243'
  tag severity: 'medium'
  tag checkid: 'C-47261r3_chk'
  tag fixid: 'F-45881r1_fix'
  tag version: 'WN12-CC-000077'
  tag ruleid: 'SV-52955r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface -> "Enumerate administrator accounts on elevation" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\

Value Name: EnumerateAdministrators

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-14243
  
    describe registry_key({
      name: 'EnumerateAdministrators',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\CredUI',
    }) do
      its("EnumerateAdministrators") { should eq 0 }
    end

# STOP_DESCRIBE V-14243

end

