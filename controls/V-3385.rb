# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3385 - The system must be configured to require case insensitivity for non-Windows subsystems.'
control 'V-3385' do
  impact 0.5
  title 'The system must be configured to require case insensitivity for non-Windows subsystems.'
  desc 'This setting controls the behavior of non-Windows subsystems when dealing with the case of arguments or commands.  Case sensitivity could lead to the access of files or commands that must be restricted.  To prevent this from happening, case insensitivity restrictions must be required.'
  tag 'stig', 'V-3385'
  tag severity: 'medium'
  tag checkid: 'C-47214r2_chk'
  tag fixid: 'F-45823r1_fix'
  tag version: 'WN12-SO-000075'
  tag ruleid: 'SV-52897r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "System objects: Require case insensitivity for non-Windows subsystems" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\Kernel\

Value Name: ObCaseInsensitive

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3385
  
    describe registry_key({
      name: 'ObCaseInsensitive',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Session Manager\Kernel',
    }) do
      its("ObCaseInsensitive") { should eq 1 }
    end

# STOP_DESCRIBE V-3385

end

