# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36700 - The password reveal button must not be displayed.'
control 'V-36700' do
  impact 0.5
  title 'The password reveal button must not be displayed.'
  desc 'Visible passwords may be seen by nearby persons, compromising them.  The password reveal button can be used to display an entered password and must not be allowed.'
  tag 'stig', 'V-36700'
  tag severity: 'medium'
  tag checkid: 'C-46869r1_chk'
  tag fixid: 'F-44815r1_fix'
  tag version: 'WN12-CC-000076'
  tag ruleid: 'SV-51740r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface -> "Do not display the password reveal button" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\CredUI\

Value Name: DisablePasswordReveal

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-36700
  
    describe registry_key({
      name: 'DisablePasswordReveal',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\CredUI',
    }) do
      its("DisablePasswordReveal") { should eq 1 }
    end

# STOP_DESCRIBE V-36700

end

