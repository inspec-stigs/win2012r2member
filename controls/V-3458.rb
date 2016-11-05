# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3458 - Remote Desktop Services must be configured to disconnect an idle session after the specified time period.'
control 'V-3458' do
  impact 0.5
  title 'Remote Desktop Services must be configured to disconnect an idle session after the specified time period.'
  desc 'This setting controls how long a session may be idle before it is automatically disconnected from the server.  Users must disconnect if they plan on being away from their terminals for extended periods of time.  Idle sessions must be disconnected after 15 minutes.'
  tag 'stig', 'V-3458'
  tag severity: 'medium'
  tag checkid: 'C-47220r2_chk'
  tag fixid: 'F-45829r1_fix'
  tag version: 'WN12-CC-000101'
  tag ruleid: 'SV-52903r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Session Time Limits -> "Set time limit for active but idle Remote Desktop Services sessions" to "Enabled", and the "Idle session limit" to 15 minutes or less, excluding "0", which equates to "Never".'
  tag checktext: 'If the following registry value does not exist or its value is set to "0" or greater than "15" minutes, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: MaxIdleTime

Type: REG_DWORD
Value: 0x000dbba0 (900000) or less but not 0'

# START_DESCRIBE V-3458
  
    describe registry_key({
      name: 'MaxIdleTime',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("MaxIdleTime") { should eq 0x000dbba0 }
    end

# STOP_DESCRIBE V-3458

end

