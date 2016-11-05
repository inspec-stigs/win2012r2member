# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21952 - NTLM must be prevented from falling back to a Null session.'
control 'V-21952' do
  impact 0.5
  title 'NTLM must be prevented from falling back to a Null session.'
  desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
  tag 'stig', 'V-21952'
  tag severity: 'medium'
  tag checkid: 'C-47483r1_chk'
  tag fixid: 'F-46103r1_fix'
  tag version: 'WN12-SO-000062'
  tag ruleid: 'SV-53177r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow LocalSystem NULL session fallback" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Control\LSA\MSV1_0\

Value Name: allownullsessionfallback

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-21952
  
    describe registry_key({
      name: 'allownullsessionfallback',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\LSA\MSV1_0',
    }) do
      its("allownullsessionfallback") { should eq 0 }
    end

# STOP_DESCRIBE V-21952

end

