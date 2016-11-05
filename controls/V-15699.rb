# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15699 - The Windows Connect Now wizards must be disabled.'
control 'V-15699' do
  impact 0.5
  title 'The Windows Connect Now wizards must be disabled.'
  desc 'Windows Connect Now provides wizards for tasks such as "Set up a wireless router or access point" and must not be available to users.  Functions such as these may allow unauthorized connections to a system and the potential for sensitive information to be compromised.'
  tag 'stig', 'V-15699'
  tag severity: 'medium'
  tag checkid: 'C-47395r2_chk'
  tag fixid: 'F-46015r2_fix'
  tag version: 'WN12-CC-000013'
  tag ruleid: 'SV-53089r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now -> "Prohibit access of the Windows Connect Now wizards" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\WCN\UI\

Value Name: DisableWcnUi

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15699
  
    describe registry_key({
      name: 'DisableWcnUi',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\WCN\UI',
    }) do
      its("DisableWcnUi") { should eq 1 }
    end

# STOP_DESCRIBE V-15699

end

