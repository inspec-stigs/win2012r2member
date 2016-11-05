# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15685 - Users must be prevented from changing installation options.'
control 'V-15685' do
  impact 0.5
  title 'Users must be prevented from changing installation options.'
  desc 'Installation options for applications are typically controlled by administrators.  This setting prevents users from changing installation options that may bypass security features.'
  tag 'stig', 'V-15685'
  tag severity: 'medium'
  tag checkid: 'C-47366r2_chk'
  tag fixid: 'F-45986r1_fix'
  tag version: 'WN12-CC-000115'
  tag ruleid: 'SV-53061r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Allow user control over installs" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Installer\

Value Name: EnableUserControl

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-15685
  
    describe registry_key({
      name: 'EnableUserControl',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Installer',
    }) do
      its("EnableUserControl") { should eq 0 }
    end

# STOP_DESCRIBE V-15685

end

