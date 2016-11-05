# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-16048 - Windows Help Ratings feedback must be turned off.'
control 'V-16048' do
  impact 0.5
  title 'Windows Help Ratings feedback must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting ensures users cannot provide ratings feedback to Microsoft for Help content.'
  tag 'stig', 'V-16048'
  tag severity: 'medium'
  tag checkid: 'C-47451r1_chk'
  tag fixid: 'F-46071r1_fix'
  tag version: 'WN12-UC-000008'
  tag ruleid: 'SV-53145r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> "Turn off Help Ratings" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\Assistance\Client\1.0\

Value Name: NoExplicitFeedback

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-16048
  
    describe registry_key({
      name: 'NoExplicitFeedback',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Policies\Microsoft\Assistance\Client\1.0',
    }) do
      its("NoExplicitFeedback") { should eq 1 }
    end

# STOP_DESCRIBE V-16048

end

