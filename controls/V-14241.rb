# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14241 - User Account Control must switch to the secure desktop when prompting for elevation.'
control 'V-14241' do
  impact 0.5
  title 'User Account Control must switch to the secure desktop when prompting for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting ensures that the elevation prompt is only used in secure desktop mode.'
  tag 'stig', 'V-14241'
  tag severity: 'medium'
  tag checkid: 'C-47258r2_chk'
  tag fixid: 'F-45878r2_fix'
  tag version: 'WN12-SO-000084'
  tag ruleid: 'SV-52952r1_rule'
  tag fixtext: 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Switch to the secure desktop when prompting for elevation" to "Enabled".'
  tag checktext: 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: PromptOnSecureDesktop

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14241
  
    describe registry_key({
      name: 'PromptOnSecureDesktop',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("PromptOnSecureDesktop") { should eq 1 }
    end

# STOP_DESCRIBE V-14241

end

