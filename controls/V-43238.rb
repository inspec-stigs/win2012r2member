# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-43238 - The display of slide shows on the lock screen must be disabled (Windows 2012 R2).'
control 'V-43238' do
  impact 0.5
  title 'The display of slide shows on the lock screen must be disabled (Windows 2012 R2).'
  desc 'Slide shows that are displayed on the lock screen could display sensitive information to unauthorized personnel.  Turning off this feature will limit access to the information to a logged on user.'
  tag 'stig', 'V-43238'
  tag severity: 'medium'
  tag checkid: 'C-49387r1_chk'
  tag fixid: 'F-49190r1_fix'
  tag version: 'WN12-CC-000138'
  tag ruleid: 'SV-56343r2_rule'
  tag fixtext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> Control Panel -> Personalization -> "Prevent enabling lock screen slide show" to "Enabled".'
  tag checktext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\

Value Name: NoLockScreenSlideshow

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-43238
  
    describe registry_key({
      name: 'NoLockScreenSlideshow',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Policies\Microsoft\Windows\Personalization',
    }) do
      its("NoLockScreenSlideshow") { should eq 1 }
    end

# STOP_DESCRIBE V-43238

end

