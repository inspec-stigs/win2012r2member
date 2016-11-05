# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3449 - Remote Desktop Services must limit users to one remote session.'
control 'V-3449' do
  impact 0.5
  title 'Remote Desktop Services must limit users to one remote session.'
  desc 'Allowing multiple Remote Desktop Services sessions could consume resources.  There is also potential to make a secondary connection to a system with compromised credentials.'
  tag 'stig', 'V-3449'
  tag severity: 'medium'
  tag checkid: 'C-46962r1_chk'
  tag fixid: 'F-45235r2_fix'
  tag version: 'WN12-CC-000131'
  tag ruleid: 'SV-52216r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Connections -> "Restrict Remote Desktop Services users to a single Remote Desktop Services Session" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\ 

Value Name: fSingleSessionPerUser 

Type: REG_DWORD 
Value: 1'

# START_DESCRIBE V-3449
  
    describe registry_key({
      name: 'fSingleSessionPerUser',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("fSingleSessionPerUser") { should eq 1 }
    end

# STOP_DESCRIBE V-3449

end

