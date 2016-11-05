# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15686 - Nonadministrators must be prevented from applying vendor-signed updates.'
control 'V-15686' do
  impact 0.1
  title 'Nonadministrators must be prevented from applying vendor-signed updates.'
  desc 'Uncontrolled system updates can introduce issues to a system.  This setting will prevent users from applying vendor-signed updates (though they may be from a trusted source).'
  tag 'stig', 'V-15686'
  tag severity: 'low'
  tag checkid: 'C-47371r2_chk'
  tag fixid: 'F-45991r1_fix'
  tag version: 'WN12-CC-000118'
  tag ruleid: 'SV-53065r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prohibit non-administrators from applying vendor signed updates" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: DisableLUAPatching

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15686
  
    describe registry_key({
      name: 'DisableLUAPatching',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Installer',
    }) do
      its("DisableLUAPatching") { should eq 1 }
    end

# STOP_DESCRIBE V-15686

end

