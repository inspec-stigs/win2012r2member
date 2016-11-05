# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26283 - Anonymous enumeration of SAM accounts must not be allowed.'
control 'V-26283' do
  impact 1.0
  title 'Anonymous enumeration of SAM accounts must not be allowed.'
  desc 'Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.'
  tag 'stig', 'V-26283'
  tag severity: 'high'
  tag checkid: 'C-47428r1_chk'
  tag fixid: 'F-46048r1_fix'
  tag version: 'WN12-SO-000051'
  tag ruleid: 'SV-53122r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Lsa\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-26283
  
    describe registry_key({
      name: 'RestrictAnonymousSAM',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Lsa',
    }) do
      its("RestrictAnonymousSAM") { should eq 1 }
    end

# STOP_DESCRIBE V-26283

end

