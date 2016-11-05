# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-6834 - Anonymous access to Named Pipes and Shares must be restricted.'
control 'V-6834' do
  impact 1.0
  title 'Anonymous access to Named Pipes and Shares must be restricted.'
  desc 'Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access.  This setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously" and "Network access: Shares that can be accessed anonymously",  both of which must be blank under other requirements.'
  tag 'stig', 'V-6834'
  tag severity: 'high'
  tag checkid: 'C-47242r2_chk'
  tag fixid: 'F-45863r1_fix'
  tag version: 'WN12-SO-000058'
  tag ruleid: 'SV-52937r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Restrict anonymous access to Named Pipes and Shares" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\LanManServer\Parameters\

Value Name: RestrictNullSessAccess

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-6834
  
    describe registry_key({
      name: 'RestrictNullSessAccess',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\LanManServer\Parameters',
    }) do
      its("RestrictNullSessAccess") { should eq 1 }
    end

# STOP_DESCRIBE V-6834

end

