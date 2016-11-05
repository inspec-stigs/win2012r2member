# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4448 - Group Policy objects must be reprocessed even if they have not changed.'
control 'V-4448' do
  impact 0.5
  title 'Group Policy objects must be reprocessed even if they have not changed.'
  desc 'Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed" option ensures that the policies will be reprocessed even if none have been changed.  This way, any unauthorized changes are forced to match the domain-based group policy settings again.'
  tag 'stig', 'V-4448'
  tag severity: 'medium'
  tag checkid: 'C-47238r3_chk'
  tag fixid: 'F-45859r1_fix'
  tag version: 'WN12-CC-000028'
  tag ruleid: 'SV-52933r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy -> "Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy objects have not changed".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\

Value Name: NoGPOListChanges

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-4448
  
    describe registry_key({
      name: 'NoGPOListChanges',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}',
    }) do
      its("NoGPOListChanges") { should eq 0 }
    end

# STOP_DESCRIBE V-4448

end

