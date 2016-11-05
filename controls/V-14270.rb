# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14270 - The system must notify antivirus when file attachments are opened.'
control 'V-14270' do
  impact 0.5
  title 'The system must notify antivirus when file attachments are opened.'
  desc 'Attaching malicious files is a known avenue of attack.  This setting configures the system to notify antivirus programs when a user opens a file attachment.'
  tag 'stig', 'V-14270'
  tag severity: 'medium'
  tag checkid: 'C-47313r2_chk'
  tag fixid: 'F-45933r1_fix'
  tag version: 'WN12-UC-000011'
  tag ruleid: 'SV-53006r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> Windows Components -> Attachment Manager -> "Notify antivirus programs when opening attachments" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\

Value Name: ScanWithAntiVirus

Type: REG_DWORD
Value: 3'

# START_DESCRIBE V-14270
  
    describe registry_key({
      name: 'ScanWithAntiVirus',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments',
    }) do
      its("ScanWithAntiVirus") { should eq 3 }
    end

# STOP_DESCRIBE V-14270

end

