# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-16021 - The Windows Help Experience Improvement Program must be disabled.'
control 'V-16021' do
  impact 0.5
  title 'The Windows Help Experience Improvement Program must be disabled.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting ensures the Windows Help Experience Improvement Program is disabled to prevent information from being passed to the vendor.'
  tag 'stig', 'V-16021'
  tag severity: 'medium'
  tag checkid: 'C-47450r1_chk'
  tag fixid: 'F-46070r1_fix'
  tag version: 'WN12-UC-000007'
  tag ruleid: 'SV-53144r1_rule'
  tag fixtext: 'Configure the policy value for User Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication Settings -> "Turn off Help Experience Improvement Program" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_CURRENT_USER
Registry Path: \Software\Policies\Microsoft\Assistance\Client\1.0\

Value Name: NoImplicitFeedback

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-16021
  
    describe registry_key({
      name: 'NoImplicitFeedback',
      hive: 'HKEY_CURRENT_USER',
      key:  'Software\Policies\Microsoft\Assistance\Client\1.0',
    }) do
      its("NoImplicitFeedback") { should eq 1 }
    end

# STOP_DESCRIBE V-16021

end

