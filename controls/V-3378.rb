# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3378 - The system must be configured to use the Classic security model.'
control 'V-3378' do
  impact 0.5
  title 'The system must be configured to use the Classic security model.'
  desc 'Windows includes two network-sharing security models - Classic and Guest only.  With the Classic model, local accounts must be password protected; otherwise, anyone can use guest user accounts to access shared system resources.'
  tag 'stig', 'V-3378'
  tag severity: 'medium'
  tag checkid: 'C-47208r2_chk'
  tag fixid: 'F-45817r1_fix'
  tag version: 'WN12-SO-000060'
  tag ruleid: 'SV-52891r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Sharing and security model for local accounts" to "Classic - local users authenticate as themselves".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: ForceGuest

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-3378
  
    describe registry_key({
      name: 'ForceGuest',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("ForceGuest") { should eq 0 }
    end

# STOP_DESCRIBE V-3378

end

