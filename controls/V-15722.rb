# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15722 - Windows Media Digital Rights Management (DRM) must be prevented from accessing the Internet.'
control 'V-15722' do
  impact 0.5
  title 'Windows Media Digital Rights Management (DRM) must be prevented from accessing the Internet.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This check verifies that Windows Media DRM will be prevented from accessing the Internet.'
  tag 'stig', 'V-15722'
  tag severity: 'medium'
  tag checkid: 'C-47445r1_chk'
  tag fixid: 'F-46065r1_fix'
  tag version: 'WN12-CC-000120'
  tag ruleid: 'SV-53139r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Digital Rights Management -> "Prevent Windows Media DRM Internet Access" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\WMDRM\

Value Name: DisableOnline

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15722
  
    describe registry_key({
      name: 'DisableOnline',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\WMDRM',
    }) do
      its("DisableOnline") { should eq 1 }
    end

# STOP_DESCRIBE V-15722

end

