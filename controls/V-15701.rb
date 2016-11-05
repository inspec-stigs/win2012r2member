# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15701 - A system restore point must be created when a new device driver is installed.'
control 'V-15701' do
  impact 0.1
  title 'A system restore point must be created when a new device driver is installed.'
  desc 'A system restore point allows a rollback if an issue is  encountered when a new device driver is installed.'
  tag 'stig', 'V-15701'
  tag severity: 'low'
  tag checkid: 'C-47405r2_chk'
  tag fixid: 'F-46025r1_fix'
  tag version: 'WN12-CC-000021'
  tag ruleid: 'SV-53099r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Prevent creation of a system restore point during device activity that would normally prompt creation of a restore point" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DeviceInstall\Settings\

Value Name: DisableSystemRestore

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15701
  
    describe registry_key({
      name: 'DisableSystemRestore',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DeviceInstall\Settings',
    }) do
      its("DisableSystemRestore") { should eq 0 }
    end

# STOP_DESCRIBE V-15701

end

