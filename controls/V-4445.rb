# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4445 - Optional Subsystems must not be permitted to operate on the system.'
control 'V-4445' do
  impact 0.1
  title 'Optional Subsystems must not be permitted to operate on the system.'
  desc 'The POSIX subsystem is an Institute of Electrical and Electronic Engineers (IEEE) standard that defines a set of operating system services.  The POSIX Subsystem is required if the server supports applications that use that subsystem.  The subsystem introduces a security risk relating to processes that can potentially persist across logins.  That is, if a user starts a process and then logs out, there is a potential that the next user who logs in to the system could access the previous users process.  This is dangerous because the process started by the first user may retain that users system privileges, and anything the second user does with that process will be performed with the privileges of the first user.'
  tag 'stig', 'V-4445'
  tag severity: 'low'
  tag checkid: 'C-46964r1_chk'
  tag fixid: 'F-45238r1_fix'
  tag version: 'WN12-SO-000088'
  tag ruleid: 'SV-52219r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System settings: Optional subsystems" to "Blank" (Configured with no entries).'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\Subsystems\

Value Name: Optional

Value Type: REG_MULTI_SZ
Value: (Blank)'

# START_DESCRIBE V-4445
  
    describe registry_key({
      name: 'Optional',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Session Manager\Subsystems',
    }) do
      its("Optional") { should eq (Blank) }
    end

# STOP_DESCRIBE V-4445

end

