# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3379 - The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
control 'V-3379' do
  impact 1.0
  title 'The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc 'The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords.  This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.'
  tag 'stig', 'V-3379'
  tag severity: 'high'
  tag checkid: 'C-47209r2_chk'
  tag fixid: 'F-45818r1_fix'
  tag version: 'WN12-SO-000065'
  tag ruleid: 'SV-52892r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: NoLMHash

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3379
  
    describe registry_key({
      name: 'NoLMHash',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("NoLMHash") { should eq 1 }
    end

# STOP_DESCRIBE V-3379

end

