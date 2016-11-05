# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14269 - Mechanisms for removing zone information from file attachments must be hidden.'
control 'V-14269' do
  impact 0.5
  title 'Mechanisms for removing zone information from file attachments must be hidden.'
  desc 'Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows Windows to determine risk.  This setting prevents users from manually removing zone information from saved file attachments.'
  tag 'stig', 'V-14269'
  tag severity: 'medium'
  tag checkid: 'C-47311r2_chk'
  tag fixid: 'F-45931r1_fix'
  tag version: 'WN12-UC-000010'
  tag ruleid: 'SV-53004r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Hide mechanisms to remove zone information" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: HideZoneInfoOnProperties

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14269
  
    describe registry_key({
      name: 'HideZoneInfoOnProperties',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments',
    }) do
      its("HideZoneInfoOnProperties") { should eq 1 }
    end

# STOP_DESCRIBE V-14269

end

