# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3374 - The system must be configured to require a strong session key.'
control 'V-3374' do
  impact 0.5
  title 'The system must be configured to require a strong session key.'
  desc 'A computer connecting to a domain controller will establish a secure channel.  Requiring strong session keys enforces 128-bit encryption between systems.'
  tag 'stig', 'V-3374'
  tag severity: 'medium'
  tag checkid: 'C-47205r2_chk'
  tag fixid: 'F-45814r1_fix'
  tag version: 'WN12-SO-000017'
  tag ruleid: 'SV-52888r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Require strong (Windows 2000 or Later) session key" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: RequireStrongKey

Value Type: REG_DWORD
Value: 1
 
This setting may prevent a system from being joined to a domain if not configured consistently between systems.'

# START_DESCRIBE V-3374
  
    describe registry_key({
      name: 'RequireStrongKey',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Netlogon\Parameters',
    }) do
      its("RequireStrongKey") { should eq 1 }
    end

# STOP_DESCRIBE V-3374

end

