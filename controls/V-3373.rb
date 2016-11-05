# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3373 - The maximum age for machine account passwords must be set to requirements.'
control 'V-3373' do
  impact 0.1
  title 'The maximum age for machine account passwords must be set to requirements.'
  desc 'Computer account passwords are changed automatically on a regular basis.  This setting controls the maximum password age that a machine account may have.  This setting must be set to no more than 30 days, ensuring the machine changes its password monthly.'
  tag 'stig', 'V-3373'
  tag severity: 'low'
  tag checkid: 'C-47204r2_chk'
  tag fixid: 'F-45813r1_fix'
  tag version: 'WN12-SO-000016'
  tag ruleid: 'SV-52887r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Maximum machine account password age" to "30" or less (excluding "0" which is unacceptable).'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: MaximumPasswordAge

Value Type: REG_DWORD
Value: 30 (or less, but not 0)'

# START_DESCRIBE V-3373
  
    describe registry_key({
      name: 'MaximumPasswordAge',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Netlogon\Parameters',
    }) do
      its("MaximumPasswordAge") { should eq 30 }
    end

# STOP_DESCRIBE V-3373

end

