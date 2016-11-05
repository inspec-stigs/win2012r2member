# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3343 - Solicited Remote Assistance must not be allowed.'
control 'V-3343' do
  impact 1.0
  title 'Solicited Remote Assistance must not be allowed.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user.  Solicited assistance is help that is specifically requested by the local user.  This may allow unauthorized parties access to the resources on the computer.'
  tag 'stig', 'V-3343'
  tag severity: 'high'
  tag checkid: 'C-47202r2_chk'
  tag fixid: 'F-45811r1_fix'
  tag version: 'WN12-CC-000059'
  tag ruleid: 'SV-52885r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Solicited Remote Assistance" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\ 

Value Name: fAllowToGetHelp
 
Type: REG_DWORD 
Value: 0'

# START_DESCRIBE V-3343
  
    describe registry_key({
      name: 'fAllowToGetHelp',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("fAllowToGetHelp") { should eq 0 }
    end

# STOP_DESCRIBE V-3343

end

