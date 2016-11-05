# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1154 - The Ctrl+Alt+Del security attention sequence for logons must be enabled.'
control 'V-1154' do
  impact 0.5
  title 'The Ctrl+Alt+Del security attention sequence for logons must be enabled.'
  desc 'Disabling the Ctrl+Alt+Del security attention sequence can compromise system security.  Because only Windows responds to the Ctrl+Alt+Del security sequence, a user can be assured that any passwords entered following that sequence are sent only to Windows.  If the sequence requirement is eliminated, malicious programs can request and receive a users Windows password.  Disabling this sequence also suppresses a custom logon banner.'
  tag 'stig', 'V-1154'
  tag severity: 'medium'
  tag checkid: 'C-47183r2_chk'
  tag fixid: 'F-45792r1_fix'
  tag version: 'WN12-SO-000019'
  tag ruleid: 'SV-52866r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Do not require CTRL+ALT+DEL" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: DisableCAD

Value Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-1154
  
    describe registry_key({
      name: 'DisableCAD',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("DisableCAD") { should eq 0 }
    end

# STOP_DESCRIBE V-1154

end

