# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3479 - The system must be configured to use Safe DLL Search Mode.'
control 'V-3479' do
  impact 0.5
  title 'The system must be configured to use Safe DLL Search Mode.'
  desc 'The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), is to search the current directory, followed by the directories contained in the systems path environment variable.  An unauthorized DLL, inserted into an applications working directory, could allow malicious code to be run on the system.  Setting this policy value forces the system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path.'
  tag 'stig', 'V-3479'
  tag severity: 'medium'
  tag checkid: 'C-47225r2_chk'
  tag fixid: 'F-45846r2_fix'
  tag version: 'WN12-SO-000045'
  tag ruleid: 'SV-52920r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)" to "Enabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\

Value Name: SafeDllSearchMode

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3479
  
    describe registry_key({
      name: 'SafeDllSearchMode',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'System\CurrentControlSet\Control\Session Manager',
    }) do
      its("SafeDllSearchMode") { should eq 1 }
    end

# STOP_DESCRIBE V-3479

end

