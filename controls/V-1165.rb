# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1165 - The computer account password must not be prevented from being reset.'
control 'V-1165' do
  impact 0.1
  title 'The computer account password must not be prevented from being reset.'
  desc 'Computer account passwords are changed automatically on a regular basis.  Disabling automatic password changes can make the system more vulnerable to malicious access.  Frequent password changes can be a significant safeguard for your system.  A new password for the computer account will be generated every 30 days.'
  tag 'stig', 'V-1165'
  tag severity: 'low'
  tag checkid: 'C-47190r2_chk'
  tag fixid: 'F-45799r1_fix'
  tag version: 'WN12-SO-000015'
  tag ruleid: 'SV-52873r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Domain member: Disable machine account password changes" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Services\Netlogon\Parameters\

Value Name: DisablePasswordChange

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-1165
  
    describe registry_key({
      name: 'DisablePasswordChange',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Services\Netlogon\Parameters',
    }) do
      its("DisablePasswordChange") { should eq 0 }
    end

# STOP_DESCRIBE V-1165

end

