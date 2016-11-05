# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15700 - Remote access to the Plug and Play interface must be disabled for device installation.'
control 'V-15700' do
  impact 0.5
  title 'Remote access to the Plug and Play interface must be disabled for device installation.'
  desc 'Remote access to the Plug and Play interface could potentially allow connections by unauthorized devices.  This setting configures remote access to the Plug and Play interface and must be disabled.'
  tag 'stig', 'V-15700'
  tag severity: 'medium'
  tag checkid: 'C-47400r2_chk'
  tag fixid: 'F-46020r1_fix'
  tag version: 'WN12-CC-000019'
  tag ruleid: 'SV-53094r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Allow remote access to the Plug and Play interface" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DeviceInstall\Settings\

Value Name: AllowRemoteRPC

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15700
  
    describe registry_key({
      name: 'AllowRemoteRPC',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DeviceInstall\Settings',
    }) do
      its("AllowRemoteRPC") { should eq 0 }
    end

# STOP_DESCRIBE V-15700

end

