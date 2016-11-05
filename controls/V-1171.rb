# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1171 - Ejection of removable NTFS media must be restricted to Administrators.'
control 'V-1171' do
  impact 0.5
  title 'Ejection of removable NTFS media must be restricted to Administrators.'
  desc 'Removable hard drives, if they are not properly configured, can be formatted and ejected by users who are not members of the Administrators Group.  Formatting and ejecting removable NTFS media must only be done by administrators.'
  tag 'stig', 'V-1171'
  tag severity: 'medium'
  tag checkid: 'C-47192r3_chk'
  tag fixid: 'F-45801r1_fix'
  tag version: 'WN12-SO-000011'
  tag ruleid: 'SV-52875r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Devices: Allowed to format and eject removable media" to "Administrators".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: AllocateDASD

Value Type: REG_SZ
Value: 0'

# START_DESCRIBE V-1171
  
    describe registry_key({
      name: 'AllocateDASD',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    }) do
      its("AllocateDASD") { should eq 0 }
    end

# STOP_DESCRIBE V-1171

end

