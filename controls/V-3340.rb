# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3340 - Network shares that can be accessed anonymously must not be allowed.'
control 'V-3340' do
  impact 1.0
  title 'Network shares that can be accessed anonymously must not be allowed.'
  desc 'Anonymous access to network shares provides the potential for gaining unauthorized system access by network users.  This could lead to the exposure or corruption of sensitive data.'
  tag 'stig', 'V-3340'
  tag severity: 'high'
  tag checkid: 'C-47201r2_chk'
  tag fixid: 'F-45810r1_fix'
  tag version: 'WN12-SO-000059'
  tag ruleid: 'SV-52884r1_rule'
  tag fixtext: 'Ensure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Shares that can be accessed anonymously" contains no entries (blank).'
  tag checktext: 'If the following registry value does not exist, this is not a finding:

If the following registry value does exist and is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: NullSessionShares

Value Type: REG_MULTI_SZ
Value: (Blank)'

# START_DESCRIBE V-3340
  
    describe registry_key({
      name: 'NullSessionShares',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LanManServer\Parameters',
    }) do
      its("NullSessionShares") { should eq (Blank) }
    end

# STOP_DESCRIBE V-3340

end

