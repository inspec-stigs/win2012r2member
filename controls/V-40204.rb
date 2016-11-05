# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40204 - Only the default client printer must be redirected to the Remote Desktop Session Host.  (Remote Desktop Services Role).'
control 'V-40204' do
  impact 0.5
  title 'Only the default client printer must be redirected to the Remote Desktop Session Host.  (Remote Desktop Services Role).'
  desc 'Allowing the redirection of only the default client printer to a Remote Desktop session helps reduce possible exposure of sensitive data.'
  tag 'stig', 'V-40204'
  tag severity: 'medium'
  tag checkid: 'C-46955r1_chk'
  tag fixid: 'F-45188r2_fix'
  tag version: 'WN12-CC-000136'
  tag ruleid: 'SV-52163r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Printer Redirection -> "Redirect only the default client printer" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: RedirectOnlyDefaultClientPrinter

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-40204
  
    describe registry_key({
      name: 'RedirectOnlyDefaultClientPrinter',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("RedirectOnlyDefaultClientPrinter") { should eq 1 }
    end

# STOP_DESCRIBE V-40204

end

