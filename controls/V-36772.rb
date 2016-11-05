# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36772 - The machine account lockout threshold must be set to 10 on systems with BitLocker enabled.'
control 'V-36772' do
  impact 0.5
  title 'The machine account lockout threshold must be set to 10 on systems with BitLocker enabled.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts should be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.'
  tag 'stig', 'V-36772'
  tag severity: 'medium'
  tag checkid: 'C-46850r1_chk'
  tag fixid: 'F-44716r1_fix'
  tag version: 'WN12-SO-000020'
  tag ruleid: 'SV-51594r1_rule'
  tag fixtext: 'If BitLocker is enabled for the OS volumes, configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Machine account lockout threshold" to "10" invalid logon attempts.'
  tag checktext: 'Verify whether BitLocker is enabled for the OS volumes in "BitLocker Drive Encryption" in Control Panel.  If BitLocker is not enabled, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: MaxDevicePasswordFailedAttempts

Value Type: REG_DWORD
Value: 0x0000000a (10)'

# START_DESCRIBE V-36772
  
    describe registry_key({
      name: 'MaxDevicePasswordFailedAttempts',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("MaxDevicePasswordFailedAttempts") { should eq 0x0000000a }
    end

# STOP_DESCRIBE V-36772

end

