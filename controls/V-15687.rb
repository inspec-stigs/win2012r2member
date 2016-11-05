# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15687 - Users must not be presented with Privacy and Installation options on first use of Windows Media Player.'
control 'V-15687' do
  impact 0.1
  title 'Users must not be presented with Privacy and Installation options on first use of Windows Media Player.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents users from being presented with Privacy and Installation options on first use of Windows Media Player, which could enable some communication with the vendor.'
  tag 'stig', 'V-15687'
  tag severity: 'low'
  tag checkid: 'C-47374r2_chk'
  tag fixid: 'F-45995r1_fix'
  tag version: 'WN12-CC-000121'
  tag ruleid: 'SV-53069r1_rule'
  tag fixtext: 'If Windows Media Player is installed, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Do Not Show First Use Dialog Boxes" to "Enabled".'
  tag checktext: 'Windows Media Player is not installed by default.  If it is not installed, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WindowsMediaPlayer\

Value Name: GroupPrivacyAcceptance

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15687
  
    describe registry_key({
      name: 'GroupPrivacyAcceptance',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\WindowsMediaPlayer',
    }) do
      its("GroupPrivacyAcceptance") { should eq 1 }
    end

# STOP_DESCRIBE V-15687

end

