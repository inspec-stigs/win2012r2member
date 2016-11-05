# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-16005 - The system must be configured to remove the Disconnect option from the Shut Down dialog box on the Remote Desktop Client.  (Remote Desktop Services Role).'
control 'V-16005' do
  impact 0.1
  title 'The system must be configured to remove the Disconnect option from the Shut Down dialog box on the Remote Desktop Client.  (Remote Desktop Services Role).'
  desc 'Removing the Disconnect option from the Shut Down dialog box for Remote Desktop sessions helps prevent disconnected but active sessions from continuing to run and using resources.'
  tag 'stig', 'V-16005'
  tag severity: 'low'
  tag checkid: 'C-46971r2_chk'
  tag fixid: 'F-45248r2_fix'
  tag version: 'WN12-CC-000137'
  tag ruleid: 'SV-52232r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Remote Session Environment -> "Remove "Disconnect" option from Shut Down dialog" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoDisconnect

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-16005
  
    describe registry_key({
      name: 'NoDisconnect',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    }) do
      its("NoDisconnect") { should eq 1 }
    end

# STOP_DESCRIBE V-16005

end

