# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21960 - Domain users must be required to elevate when setting a networks location.'
control 'V-21960' do
  impact 0.1
  title 'Domain users must be required to elevate when setting a networks location.'
  desc 'Selecting an incorrect network location may allow greater exposure of a system.  Elevation is required by default on nondomain systems to change network location.  This setting configures elevation to also be required on domain-joined systems.'
  tag 'stig', 'V-21960'
  tag severity: 'low'
  tag checkid: 'C-47488r1_chk'
  tag fixid: 'F-46108r1_fix'
  tag version: 'WN12-CC-000005'
  tag ruleid: 'SV-53182r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections -> "Require domain users to elevate when setting a networks location" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Network Connections\

Value Name: NC_StdDomainUserSetLocation

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-21960
  
    describe registry_key({
      name: 'NC_StdDomainUserSetLocation',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Network Connections',
    }) do
      its("NC_StdDomainUserSetLocation") { should eq 1 }
    end

# STOP_DESCRIBE V-21960

end

