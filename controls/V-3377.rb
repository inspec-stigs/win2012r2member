# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3377 - The system must be configured to prevent anonymous users from having the same rights as the Everyone group.'
control 'V-3377' do
  impact 0.5
  title 'The system must be configured to prevent anonymous users from having the same rights as the Everyone group.'
  desc 'Access by anonymous users must be restricted.  If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users must not have these permissions or rights.'
  tag 'stig', 'V-3377'
  tag severity: 'medium'
  tag checkid: 'C-47207r2_chk'
  tag fixid: 'F-45816r1_fix'
  tag version: 'WN12-SO-000054'
  tag ruleid: 'SV-52890r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Let everyone permissions apply to anonymous users" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-3377
  
    describe registry_key({
      name: 'EveryoneIncludesAnonymous',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("EveryoneIncludesAnonymous") { should eq 0 }
    end

# STOP_DESCRIBE V-3377

end

