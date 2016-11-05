# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15727 - Users must be prevented from sharing files in their profiles.'
control 'V-15727' do
  impact 0.5
  title 'Users must be prevented from sharing files in their profiles.'
  desc 'Allowing users to share files in their profiles may provide unauthorized access or result in the exposure of sensitive data.'
  tag 'stig', 'V-15727'
  tag severity: 'medium'
  tag checkid: 'C-47446r1_chk'
  tag fixid: 'F-46066r1_fix'
  tag version: 'WN12-UC-000012'
  tag ruleid: 'SV-53140r2_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Network Sharing -> "Prevent users from sharing files within their profile" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoInPlaceSharing

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15727
  
    describe registry_key({
      name: 'NoInPlaceSharing',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    }) do
      its("NoInPlaceSharing") { should eq 1 }
    end

# STOP_DESCRIBE V-15727

end

