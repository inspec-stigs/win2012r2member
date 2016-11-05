# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14268 - Zone information must be preserved when saving attachments.'
control 'V-14268' do
  impact 0.5
  title 'Zone information must be preserved when saving attachments.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.'
  tag 'stig', 'V-14268'
  tag severity: 'medium'
  tag checkid: 'C-47309r2_chk'
  tag fixid: 'F-45929r1_fix'
  tag version: 'WN12-UC-000009'
  tag ruleid: 'SV-53002r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Do not preserve zone information in file attachments" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: SaveZoneInformation

Type: REG_DWORD
Value: 2'

# START_DESCRIBE V-14268
  
    describe registry_key({
      name: 'SaveZoneInformation',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments',
    }) do
      its("SaveZoneInformation") { should eq 2 }
    end

# STOP_DESCRIBE V-14268

end

