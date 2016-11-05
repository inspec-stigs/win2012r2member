# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26580 - The Security event log size must be configured to 196608 KB or greater.'
control 'V-26580' do
  impact 0.5
  title 'The Security event log size must be configured to 196608 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  tag 'stig', 'V-26580'
  tag severity: 'medium'
  tag checkid: 'C-66233r1_chk'
  tag fixid: 'F-71603r2_fix'
  tag version: 'WN12-CC-000085'
  tag ruleid: 'SV-52965r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "196608" or greater.'
  tag checktext: 'If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00030000 (196608) (or greater)'

# START_DESCRIBE V-26580
  
    describe registry_key({
      name: 'MaxSize',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security',
    }) do
      its("MaxSize") { should eq 0x00030000 }
    end

# STOP_DESCRIBE V-26580

end

