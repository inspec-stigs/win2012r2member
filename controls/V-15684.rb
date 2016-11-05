# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15684 - Users must be notified if a web-based program attempts to install software.'
control 'V-15684' do
  impact 0.5
  title 'Users must be notified if a web-based program attempts to install software.'
  desc 'Users must be aware of attempted program installations.  This setting ensures users are notified if a web-based program attempts to install software.'
  tag 'stig', 'V-15684'
  tag severity: 'medium'
  tag checkid: 'C-47359r2_chk'
  tag fixid: 'F-45982r1_fix'
  tag version: 'WN12-CC-000117'
  tag ruleid: 'SV-53056r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Prevent Internet Explorer security prompt for Windows Installer scripts" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: SafeForScripting

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15684
  
    describe registry_key({
      name: 'SafeForScripting',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Installer',
    }) do
      its("SafeForScripting") { should eq 0 }
    end

# STOP_DESCRIBE V-15684

end

