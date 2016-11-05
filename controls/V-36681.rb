# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36681 - Copying of user input methods to the system account for sign-in must be prevented.'
control 'V-36681' do
  impact 0.5
  title 'Copying of user input methods to the system account for sign-in must be prevented.'
  desc 'Allowing different input methods for sign-in could open different avenues of attack.  User input methods must be restricted to those enabled for the system account at sign-in.'
  tag 'stig', 'V-36681'
  tag severity: 'medium'
  tag checkid: 'C-46861r1_chk'
  tag fixid: 'F-44731r1_fix'
  tag version: 'WN12-CC-000048'
  tag ruleid: 'SV-51610r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Locale Services -> "Disallow copying of user input methods to the system account for sign-in" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Control Panel\International\

Value Name: BlockUserInputMethodsForSignIn

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36681
  
    describe registry_key({
      name: 'BlockUserInputMethodsForSignIn',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Control Panel\International',
    }) do
      its("BlockUserInputMethodsForSignIn") { should eq 1 }
    end

# STOP_DESCRIBE V-36681

end

