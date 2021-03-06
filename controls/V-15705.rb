# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15705 - Users must be prompted to authenticate on resume from sleep (on battery).'
control 'V-15705' do
  impact 0.5
  title 'Users must be prompted to authenticate on resume from sleep (on battery).'
  desc 'Authentication must always be required when accessing a system.  This setting ensures the user is prompted for a password on resume from sleep (on battery).'
  tag 'stig', 'V-15705'
  tag severity: 'medium'
  tag checkid: 'C-47437r1_chk'
  tag fixid: 'F-46057r1_fix'
  tag version: 'WN12-CC-000054'
  tag ruleid: 'SV-53131r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings -> "Require a password when a computer wakes (on battery)" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\

Value Name: DCSettingIndex

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15705
  
    describe registry_key({
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51',
    }) do
      its("DCSettingIndex") { should eq 1 }
    end

# STOP_DESCRIBE V-15705

end

