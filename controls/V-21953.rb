# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21953 - PKU2U authentication using online identities must be prevented.'
control 'V-21953' do
  impact 0.5
  title 'PKU2U authentication using online identities must be prevented.'
  desc 'PKU2U is a peer-to-peer authentication protocol.   This setting prevents online identities from authenticating to domain-joined systems.  Authentication will be centrally managed with Windows user accounts.'
  tag 'stig', 'V-21953'
  tag severity: 'medium'
  tag checkid: 'C-47484r1_chk'
  tag fixid: 'F-46104r1_fix'
  tag version: 'WN12-SO-000063'
  tag ruleid: 'SV-53178r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \System\CurrentControlSet\Control\LSA\pku2u\

Value Name: AllowOnlineID

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-21953
  
    describe registry_key({
      name: 'AllowOnlineID',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\LSA\pku2u',
    }) do
      its("AllowOnlineID") { should eq 0 }
    end

# STOP_DESCRIBE V-21953

end

