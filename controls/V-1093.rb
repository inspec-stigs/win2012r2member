# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1093 - Anonymous enumeration of shares must be restricted.'
control 'V-1093' do
  impact 1.0
  title 'Anonymous enumeration of shares must be restricted.'
  desc 'Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.'
  tag 'stig', 'V-1093'
  tag severity: 'high'
  tag checkid: 'C-47164r2_chk'
  tag fixid: 'F-45773r1_fix'
  tag version: 'WN12-SO-000052'
  tag ruleid: 'SV-52847r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-1093
  
    describe registry_key({
      name: 'RestrictAnonymous',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("RestrictAnonymous") { should eq 1 }
    end

# STOP_DESCRIBE V-1093

end

