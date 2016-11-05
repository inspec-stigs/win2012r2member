# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15999 - Users must be prevented from redirecting Plug and Play devices to the Remote Desktop Session Host.  (Remote Desktop Services Role).'
control 'V-15999' do
  impact 0.5
  title 'Users must be prevented from redirecting Plug and Play devices to the Remote Desktop Session Host.  (Remote Desktop Services Role).'
  desc 'Preventing the redirection of Plug and Play devices in Remote Desktop sessions helps reduce possible exposure of sensitive data.'
  tag 'stig', 'V-15999'
  tag severity: 'medium'
  tag checkid: 'C-46969r1_chk'
  tag fixid: 'F-45246r2_fix'
  tag version: 'WN12-CC-000135'
  tag ruleid: 'SV-52229r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection -> "Do not allow supported Plug and Play device redirection" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fDisablePNPRedir

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15999
  
    describe registry_key({
      name: 'fDisablePNPRedir',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("fDisablePNPRedir") { should eq 1 }
    end

# STOP_DESCRIBE V-15999

end

