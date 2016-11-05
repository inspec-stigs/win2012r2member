# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-43245 - Automatically signing in the last interactive user after a system-initiated restart must be disabled (Windows 2012 R2).'
control 'V-43245' do
  impact 0.5
  title 'Automatically signing in the last interactive user after a system-initiated restart must be disabled (Windows 2012 R2).'
  desc 'Windows 2012 R2 can be configured to automatically sign the user back in after a Windows Update restart.  Some protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent the caching of credentials for this purpose and also ensure the user is aware of the restart.'
  tag 'stig', 'V-43245'
  tag severity: 'medium'
  tag checkid: 'C-49391r1_chk'
  tag fixid: 'F-49196r1_fix'
  tag version: 'WN12-CC-000145'
  tag ruleid: 'SV-56355r2_rule'
  tag fixtext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Logon Options -> "Sign-in last interactive user automatically after a system-initiated restart" to "Disabled".'
  tag checktext: 'This requirement is NA for the initial release of Windows 2012.  It is applicable to Windows 2012 R2.

Verify the registry value below.  If it does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name: DisableAutomaticRestartSignOn

Value Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-43245
  
    describe registry_key({
      name: 'DisableAutomaticRestartSignOn',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    }) do
      its("DisableAutomaticRestartSignOn") { should eq 1 }
    end

# STOP_DESCRIBE V-43245

end

