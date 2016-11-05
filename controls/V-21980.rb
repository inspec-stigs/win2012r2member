# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21980 - Explorer Data Execution Prevention must be enabled.'
control 'V-21980' do
  impact 0.5
  title 'Explorer Data Execution Prevention must be enabled.'
  desc 'Data Execution Prevention (DEP) provides additional protection by performing  checks on memory to help prevent malicious code from running.  This setting will prevent Data Execution Prevention from being turned off for File Explorer.'
  tag 'stig', 'V-21980'
  tag severity: 'medium'
  tag checkid: 'C-47431r1_chk'
  tag fixid: 'F-46051r1_fix'
  tag version: 'WN12-CC-000089'
  tag ruleid: 'SV-53125r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off Data Execution Prevention for Explorer" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\Explorer\

Value Name: NoDataExecutionPrevention

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-21980
  
    describe registry_key({
      name: 'NoDataExecutionPrevention',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\Explorer',
    }) do
      its("NoDataExecutionPrevention") { should eq 0 }
    end

# STOP_DESCRIBE V-21980

end

