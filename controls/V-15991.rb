# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15991 - UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.'
control 'V-15991' do
  impact 0.5
  title 'UIAccess applications must not be allowed to prompt for elevation without using the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting prevents User Interface Accessibility programs from disabling the secure desktop for elevation prompts.'
  tag 'stig', 'V-15991'
  tag severity: 'medium'
  tag checkid: 'C-46966r1_chk'
  tag fixid: 'F-45241r1_fix'
  tag version: 'WN12-SO-000086'
  tag ruleid: 'SV-52223r2_rule'
  tag fixtext: 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop" to "Disabled".'
  tag checktext: 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: EnableUIADesktopToggle

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15991
  
    describe registry_key({
      name: 'EnableUIADesktopToggle',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("EnableUIADesktopToggle") { should eq 0 }
    end

# STOP_DESCRIBE V-15991

end

