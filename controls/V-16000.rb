# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-16000 - The system must be configured to ensure smart card devices can be redirected to the Remote Desktop session.  (Remote Desktop Services Role).'
control 'V-16000' do
  impact 0.5
  title 'The system must be configured to ensure smart card devices can be redirected to the Remote Desktop session.  (Remote Desktop Services Role).'
  desc 'Enabling the redirection of smart card devices allows their use within Remote Desktop sessions.'
  tag 'stig', 'V-16000'
  tag severity: 'medium'
  tag checkid: 'C-46970r1_chk'
  tag fixid: 'F-45247r2_fix'
  tag version: 'WN12-CC-000134'
  tag ruleid: 'SV-52230r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow smart card device redirection" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fEnableSmartCard

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-16000
  
    describe registry_key({
      name: 'fEnableSmartCard',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("fEnableSmartCard") { should eq 1 }
    end

# STOP_DESCRIBE V-16000

end

