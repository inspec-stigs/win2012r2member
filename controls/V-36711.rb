# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36711 - The Windows Store application must be turned off.'
control 'V-36711' do
  impact 0.5
  title 'The Windows Store application must be turned off.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and provide access to sensitive information.  Installation of applications must be controlled by the enterprise.  Turning off access to the Windows Store will limit access to publicly available applications.'
  tag 'stig', 'V-36711'
  tag severity: 'medium'
  tag checkid: 'C-58005r1_chk'
  tag fixid: 'F-62333r1_fix'
  tag version: 'WN12-CC-000110'
  tag ruleid: 'SV-51751r2_rule'
  tag fixtext: 'The Windows Store is not installed by default.  If the \Windows\WinStore directory does not exist, this is NA.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Store -> "Turn off the Store application" to "Enabled".'
  tag checktext: 'The Windows Store is not installed by default. If the \Windows\WinStore directory does not exist, this is NA.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\WindowsStore\

Value Name:  RemoveWindowsStore

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-36711
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36711

end

