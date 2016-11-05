# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1158 - The Recovery Console SET command must be disabled.'
control 'V-1158' do
  impact 0.1
  title 'The Recovery Console SET command must be disabled.'
  desc 'The Recovery Console SET command allows environment variables to be set in the Recovery Console.  This permits access to all drives and folders  and the copying of files to removable media, which could expose sensitive information.'
  tag 'stig', 'V-1158'
  tag severity: 'low'
  tag checkid: 'C-47185r3_chk'
  tag fixid: 'F-45794r2_fix'
  tag version: 'WN12-SO-000072'
  tag ruleid: 'SV-52868r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Recovery Console: Allow floppy copy and access to all drives and all folders" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\

Value Name:  SetCommand

Value Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-1158
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1158

end

