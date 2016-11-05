# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-28504 - Windows must be prevented from sending an error report when a device driver requests additional software during installation.'
control 'V-28504' do
  impact 0.1
  title 'Windows must be prevented from sending an error report when a device driver requests additional software during installation.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting will prevent Windows from sending an error report to Microsoft when a device driver requests additional software during installation.'
  tag 'stig', 'V-28504'
  tag severity: 'low'
  tag checkid: 'C-47268r1_chk'
  tag fixid: 'F-45888r1_fix'
  tag version: 'WN12-CC-000023'
  tag ruleid: 'SV-52962r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Prevent Windows from sending an error report when a device driver requests additional software during installation" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \Software\Policies\Microsoft\Windows\DeviceInstall\Settings\

Value Name: DisableSendRequestAdditionalSoftwareToWER

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-28504
  
    describe registry_key({
      name: 'DisableSendRequestAdditionalSoftwareToWER',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DeviceInstall\Settings',
    }) do
      its("DisableSendRequestAdditionalSoftwareToWER") { should eq 1 }
    end

# STOP_DESCRIBE V-28504

end

