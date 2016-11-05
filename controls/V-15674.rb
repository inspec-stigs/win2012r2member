# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15674 - The Internet File Association service must be turned off.'
control 'V-15674' do
  impact 0.5
  title 'The Internet File Association service must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents unhandled file associations from using the Microsoft Web service to find an application.'
  tag 'stig', 'V-15674'
  tag severity: 'medium'
  tag checkid: 'C-47327r2_chk'
  tag fixid: 'F-45947r1_fix'
  tag version: 'WN12-CC-000038'
  tag ruleid: 'SV-53021r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Internet File Association service" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\

Value Name: NoInternetOpenWith

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15674
  
    describe registry_key({
      name: 'NoInternetOpenWith',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    }) do
      its("NoInternetOpenWith") { should eq 1 }
    end

# STOP_DESCRIBE V-15674

end

