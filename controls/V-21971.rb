# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21971 - The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.'
control 'V-21971' do
  impact 0.1
  title 'The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.'
  tag 'stig', 'V-21971'
  tag severity: 'low'
  tag checkid: 'C-47433r1_chk'
  tag fixid: 'F-46053r1_fix'
  tag version: 'WN12-CC-000071'
  tag ruleid: 'SV-53127r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Application Compatibility -> "Turn off Inventory Collector" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\AppCompat\

Value Name: DisableInventory

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-21971
  
    describe registry_key({
      name: 'DisableInventory',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\AppCompat',
    }) do
      its("DisableInventory") { should eq 1 }
    end

# STOP_DESCRIBE V-21971

end

