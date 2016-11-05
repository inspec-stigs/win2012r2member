# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3376 - The system must be configured to prevent the storage of passwords and credentials.'
control 'V-3376' do
  impact 0.5
  title 'The system must be configured to prevent the storage of passwords and credentials.'
  desc 'This setting controls the storage of passwords and credentials for network authentication on the local system.  Such credentials must not be stored on the local machine, as that may lead to account compromise.'
  tag 'stig', 'V-3376'
  tag severity: 'medium'
  tag checkid: 'C-47206r2_chk'
  tag fixid: 'F-45815r1_fix'
  tag version: 'WN12-SO-000053'
  tag ruleid: 'SV-52889r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow storage of passwords and credentials for network authentication" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: DisableDomainCreds

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3376
  
    describe registry_key({
      name: 'DisableDomainCreds',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("DisableDomainCreds") { should eq 1 }
    end

# STOP_DESCRIBE V-3376

end

