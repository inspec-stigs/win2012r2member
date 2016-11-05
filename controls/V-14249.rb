# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14249 - Local drives must be prevented from sharing with Remote Desktop Session Hosts.  (Remote Desktop Services Role).'
control 'V-14249' do
  impact 0.5
  title 'Local drives must be prevented from sharing with Remote Desktop Session Hosts.  (Remote Desktop Services Role).'
  desc 'Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they access helps reduce possible exposure of sensitive data.'
  tag 'stig', 'V-14249'
  tag severity: 'medium'
  tag checkid: 'C-47265r2_chk'
  tag fixid: 'F-45885r1_fix'
  tag version: 'WN12-CC-000098'
  tag ruleid: 'SV-52959r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow drive redirection" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fDisableCdm

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-14249
  
    describe registry_key({
      name: 'fDisableCdm',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("fDisableCdm") { should eq 1 }
    end

# STOP_DESCRIBE V-14249

end

