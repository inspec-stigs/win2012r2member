# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36773 - The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
control 'V-36773' do
  impact 0.5
  title 'The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.'
  desc 'Unattended systems are susceptible to unauthorized use and should be locked when unattended.  The screen saver should be set at a maximum of 15 minutes and be password protected.  This protects critical and sensitive data from exposure to unauthorized personnel with physical access to the computer.'
  tag 'stig', 'V-36773'
  tag severity: 'medium'
  tag checkid: 'C-46851r1_chk'
  tag fixid: 'F-44717r1_fix'
  tag version: 'WN12-SO-000021'
  tag ruleid: 'SV-51596r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive logon: Machine inactivity limit" to "900" seconds" or less.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: InactivityTimeoutSecs

Value Type: REG_DWORD
Value: 0x00000384 (900) (or less)'

# START_DESCRIBE V-36773
  
    describe registry_key({
      name: 'InactivityTimeoutSecs',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("InactivityTimeoutSecs") { should eq 0x00000384 }
    end

# STOP_DESCRIBE V-36773

end

