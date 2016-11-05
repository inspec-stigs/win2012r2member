# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36708 - The location feature must be turned off.'
control 'V-36708' do
  impact 0.5
  title 'The location feature must be turned off.'
  desc 'The location service on systems may allow sensitive data to be used by applications on the system.  This should be turned off unless explicitly allowed for approved systems/applications.'
  tag 'stig', 'V-36708'
  tag severity: 'medium'
  tag checkid: 'C-46877r2_chk'
  tag fixid: 'F-44823r2_fix'
  tag version: 'WN12-CC-000095'
  tag ruleid: 'SV-51748r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Location and Sensors -> "Turn off location" to "Enabled".

If location services are approved by the organization for a device, this must be documented.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\LocationAndSensors\

Value Name: DisableLocation

Type: REG_DWORD
Value: 1 (Enabled)

If location services are approved for the system by the organization, this may be set to "Disabled" (0).  This must be documented with the ISSO.'

# START_DESCRIBE V-36708
  
    describe registry_key({
      name: 'DisableLocation',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\LocationAndSensors',
    }) do
      its("DisableLocation") { should eq 1 }
    end

# STOP_DESCRIBE V-36708

end

