# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-22692 - The default Autorun behavior must be configured to prevent Autorun commands.'
control 'V-22692' do
  impact 1.0
  title 'The default Autorun behavior must be configured to prevent Autorun commands.'
  desc 'Allowing Autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents Autorun commands from executing.'
  tag 'stig', 'V-22692'
  tag severity: 'high'
  tag checkid: 'C-47430r1_chk'
  tag fixid: 'F-46050r1_fix'
  tag version: 'WN12-CC-000073'
  tag ruleid: 'SV-53124r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> AutoPlay Policies -> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoAutorun

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-22692
  
    describe registry_key({
      name: 'NoAutorun',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    }) do
      its("NoAutorun") { should eq 1 }
    end

# STOP_DESCRIBE V-22692

end

