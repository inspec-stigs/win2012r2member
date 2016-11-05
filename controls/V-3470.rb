# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3470 - The system must be configured to prevent unsolicited remote assistance offers.'
control 'V-3470' do
  impact 0.5
  title 'The system must be configured to prevent unsolicited remote assistance offers.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user.  Unsolicited remote assistance is help that is offered by the remote user.  This may allow unauthorized parties access to the resources on the computer.'
  tag 'stig', 'V-3470'
  tag severity: 'medium'
  tag checkid: 'C-47222r2_chk'
  tag fixid: 'F-45843r1_fix'
  tag version: 'WN12-CC-000058'
  tag ruleid: 'SV-52917r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Offer Remote Assistance" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: fAllowUnsolicited

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-3470
  
    describe registry_key({
      name: 'fAllowUnsolicited',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("fAllowUnsolicited") { should eq 0 }
    end

# STOP_DESCRIBE V-3470

end

