# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-4442 - The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.'
control 'V-4442' do
  impact 0.1
  title 'The system must be configured to have password protection take effect within a limited time frame when the screen saver becomes active.'
  desc 'Allowing more than several seconds makes the computer vulnerable to a potential attack from someone walking up to the console to attempt to log on to the system before the lock takes effect.'
  tag 'stig', 'V-4442'
  tag severity: 'low'
  tag checkid: 'C-47235r2_chk'
  tag fixid: 'F-45856r2_fix'
  tag version: 'WN12-SO-000046'
  tag ruleid: 'SV-52930r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)" to "5" or less.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the systems policy tools.)'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \Software\Microsoft\Windows NT\CurrentVersion\Winlogon\

Value Name: ScreenSaverGracePeriod

Value Type: REG_SZ
Value: 5 (or less)'

# START_DESCRIBE V-4442
  
    describe registry_key({
      name: 'ScreenSaverGracePeriod',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
    }) do
      its("ScreenSaverGracePeriod") { should eq 5 }
    end

# STOP_DESCRIBE V-4442

end

