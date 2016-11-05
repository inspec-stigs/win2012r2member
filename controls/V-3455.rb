# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3455 - Remote Desktop Services must be configured to use session-specific temporary folders.'
control 'V-3455' do
  impact 0.5
  title 'Remote Desktop Services must be configured to use session-specific temporary folders.'
  desc 'If a communal temporary folder is used for remote desktop sessions, it might be possible for users to access other users temporary folders.  If this setting is enabled, only one temporary folder is used for all remote desktop sessions.  Per session temporary folders must be established.'
  tag 'stig', 'V-3455'
  tag severity: 'medium'
  tag checkid: 'C-47217r2_chk'
  tag fixid: 'F-45826r1_fix'
  tag version: 'WN12-CC-000104'
  tag ruleid: 'SV-52900r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Temporary Folders -> "Do not use temporary folders per session" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: PerSessionTempDir

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3455
  
    describe registry_key({
      name: 'PerSessionTempDir',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("PerSessionTempDir") { should eq 1 }
    end

# STOP_DESCRIBE V-3455

end

