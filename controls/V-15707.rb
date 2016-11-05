# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15707 - Remote Assistance log files must be generated.'
control 'V-15707' do
  impact 0.1
  title 'Remote Assistance log files must be generated.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  This setting will turn on session logging for Remote Assistance connections.'
  tag 'stig', 'V-15707'
  tag severity: 'low'
  tag checkid: 'C-47439r1_chk'
  tag fixid: 'F-46059r1_fix'
  tag version: 'WN12-CC-000062'
  tag ruleid: 'SV-53133r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Turn on session logging" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows NT\Terminal Services\

Value Name: LoggingEnabled

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15707
  
    describe registry_key({
      name: 'LoggingEnabled',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows NT\Terminal Services',
    }) do
      its("LoggingEnabled") { should eq 1 }
    end

# STOP_DESCRIBE V-15707

end

