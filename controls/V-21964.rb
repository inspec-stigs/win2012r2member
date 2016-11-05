# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-21964 - Device metadata retrieval from the Internet must be prevented.'
control 'V-21964' do
  impact 0.1
  title 'Device metadata retrieval from the Internet must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting will prevent Windows from retrieving device metadata from the Internet.'
  tag 'stig', 'V-21964'
  tag severity: 'low'
  tag checkid: 'C-47491r3_chk'
  tag fixid: 'F-46111r3_fix'
  tag version: 'WN12-CC-000022'
  tag ruleid: 'SV-53185r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Installation >> "Prevent device metadata retrieval from the Internet" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Device Metadata\

Value Name:  PreventDeviceMetadataFromNetwork

Value Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-21964
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-21964

end

