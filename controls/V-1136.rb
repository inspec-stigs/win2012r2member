# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1136 - Users must be forcibly disconnected when their logon hours expire.'
control 'V-1136' do
  impact 0.1
  title 'Users must be forcibly disconnected when their logon hours expire.'
  desc 'Users must not be permitted to remain logged on to the network after they have exceeded their permitted logon hours.  In many cases, this indicates that a user forgot to log off before leaving for the day.  However, it may also indicate that a user is attempting unauthorized access at a time when the system may be less closely monitored.  Forcibly disconnecting users when logon hours expire protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  tag 'stig', 'V-1136'
  tag severity: 'low'
  tag checkid: 'C-47177r2_chk'
  tag fixid: 'F-45786r1_fix'
  tag version: 'WN12-SO-000034'
  tag ruleid: 'SV-52860r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Microsoft network server: Disconnect clients when logon hours expire" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: EnableForcedLogoff

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-1136
  
    describe registry_key({
      name: 'EnableForcedLogoff',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LanManServer\Parameters',
    }) do
      its("EnableForcedLogoff") { should eq 1 }
    end

# STOP_DESCRIBE V-1136

end

