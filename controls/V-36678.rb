# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36678 - Device driver updates must only search managed servers, not Windows Update.'
control 'V-36678' do
  impact 0.1
  title 'Device driver updates must only search managed servers, not Windows Update.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Device driver updates must be obtained from an internal source.'
  tag 'stig', 'V-36678'
  tag severity: 'low'
  tag checkid: 'C-46858r1_chk'
  tag fixid: 'F-44728r1_fix'
  tag version: 'WN12-CC-000025'
  tag ruleid: 'SV-51607r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Specify the search server for device driver updates" to "Enabled" with "Search Managed Server" selected.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\DriverSearching\

Value Name: DriverServerSelection

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36678
  
    describe registry_key({
      name: 'DriverServerSelection',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\DriverSearching',
    }) do
      its("DriverServerSelection") { should eq 1 }
    end

# STOP_DESCRIBE V-36678

end

