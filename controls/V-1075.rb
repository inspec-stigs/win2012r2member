# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1075 - The shutdown option must not be available from the logon dialog box.'
control 'V-1075' do
  impact 0.1
  title 'The shutdown option must not be available from the logon dialog box.'
  desc 'Displaying the shutdown button may allow individuals to shut down a system anonymously.  Only authenticated users should be allowed to shut down the system.  Preventing display of this button in the logon dialog box ensures that individuals who shut down the system are authorized and tracked in the systems Security event log.'
  tag 'stig', 'V-1075'
  tag severity: 'low'
  tag checkid: 'C-47157r2_chk'
  tag fixid: 'F-45766r1_fix'
  tag version: 'WN12-SO-000073'
  tag ruleid: 'SV-52840r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Shutdown: Allow system to be shutdown without having to log on" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: ShutdownWithoutLogon

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-1075
  
    describe registry_key({
      name: 'ShutdownWithoutLogon',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("ShutdownWithoutLogon") { should eq 0 }
    end

# STOP_DESCRIBE V-1075

end

