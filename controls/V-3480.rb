# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3480 - Windows Media Player must be configured to prevent automatic checking for updates.'
control 'V-3480' do
  impact 0.5
  title 'Windows Media Player must be configured to prevent automatic checking for updates.'
  desc 'Uncontrolled system updates can introduce issues to a system.  The automatic check for updates performed by Windows Media Player must be disabled to ensure a constant platform and to prevent the introduction of unknown\untested software on the system.'
  tag 'stig', 'V-3480'
  tag severity: 'medium'
  tag checkid: 'C-47436r1_chk'
  tag fixid: 'F-46056r1_fix'
  tag version: 'WN12-CC-000122'
  tag ruleid: 'SV-53130r1_rule'
  tag fixtext: 'If Windows Media Player is installed, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Prevent Automatic Updates" to "Enabled".'
  tag checktext: 'Windows Media Player is not installed by default.  If it is not installed, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsMediaPlayer\

Value Name: DisableAutoupdate

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-3480
  
    describe registry_key({
      name: 'DisableAutoupdate',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\WindowsMediaPlayer',
    }) do
      its("DisableAutoupdate") { should eq 1 }
    end

# STOP_DESCRIBE V-3480

end

