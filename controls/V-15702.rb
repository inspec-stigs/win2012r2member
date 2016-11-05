# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15702 - An Error Report must not be sent when a generic device driver is installed.'
control 'V-15702' do
  impact 0.1
  title 'An Error Report must not be sent when a generic device driver is installed.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents an error report from being sent when a generic device driver is installed.'
  tag 'stig', 'V-15702'
  tag severity: 'low'
  tag checkid: 'C-47410r2_chk'
  tag fixid: 'F-46030r1_fix'
  tag version: 'WN12-CC-000020'
  tag ruleid: 'SV-53105r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Do not send a Windows error report when a generic driver is installed on a device" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DeviceInstall\Settings\

Value Name: DisableSendGenericDriverNotFoundToWER

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15702
  
    describe registry_key({
      name: 'DisableSendGenericDriverNotFoundToWER',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DeviceInstall\Settings',
    }) do
      its("DisableSendGenericDriverNotFoundToWER") { should eq 1 }
    end

# STOP_DESCRIBE V-15702

end

