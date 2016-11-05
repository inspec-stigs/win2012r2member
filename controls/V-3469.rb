# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3469 - Group Policies must be refreshed in the background if the user is logged on.'
control 'V-3469' do
  impact 0.5
  title 'Group Policies must be refreshed in the background if the user is logged on.'
  desc 'If this setting is enabled, then Group Policy settings are not refreshed while a user is currently logged on.  This could lead to instances when a user does not have the latest changes to a policy applied and is therefore operating in an insecure context.'
  tag 'stig', 'V-3469'
  tag severity: 'medium'
  tag checkid: 'C-47221r2_chk'
  tag fixid: 'F-45832r1_fix'
  tag version: 'WN12-CC-000029'
  tag ruleid: 'SV-52906r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy -> "Turn off background refresh of Group Policy" to "Disabled".'
  tag checktext: 'Review the registry.
If the following registry value does not exist, this is not a finding (this is the expected result from configuring the policy as outlined in the Fix section.):
If the following registry value exists but is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\system\

Value Name: DisableBkGndGroupPolicy

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-3469
  
    describe registry_key({
      name: 'DisableBkGndGroupPolicy',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\system',
    }) do
      its("DisableBkGndGroupPolicy") { should eq 0 }
    end

# STOP_DESCRIBE V-3469

end

