# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36439 - Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.'
control 'V-36439' do
  impact 0.5
  title 'Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems.'
  desc 'A compromised local administrator account can provide means for an attacker to move laterally between domain systems.    With User Account Control enabled, filtering the privileged token for local administrator accounts will prevent the elevated privileges of these accounts from being used over the network.'
  tag 'stig', 'V-36439'
  tag severity: 'medium'
  tag checkid: 'C-46849r2_chk'
  tag fixid: 'F-44715r2_fix'
  tag version: 'WN12-RG-000003-MS'
  tag ruleid: 'SV-51590r2_rule'
  tag fixtext: 'Configure the following registry value:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

Value Name:  LocalAccountTokenFilterPolicy

Type:  REG_DWORD
Value:  0'
  tag checktext: 'If the system is not a member of a domain, this is NA. 
If the following registry value does not exist or is not configured as specified, this is a finding: 

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

Value Name:  LocalAccountTokenFilterPolicy

Type:  REG_DWORD
Value:  0

This setting may cause issues with some network scanning tools if local administrative accounts are used remotely. Scans should use domain accounts where possible. If a local administrative account must be used, temporarily enabling the privileged token by configuring the registry value to 1 may be required.'

# START_DESCRIBE V-36439
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36439

end

