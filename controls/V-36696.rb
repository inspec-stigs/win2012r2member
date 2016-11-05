# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36696 - The detection of compatibility issues for applications and drivers must be turned off.'
control 'V-36696' do
  impact 0.1
  title 'The detection of compatibility issues for applications and drivers must be turned off.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this feature will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.'
  tag 'stig', 'V-36696'
  tag severity: 'low'
  tag checkid: 'C-46866r1_chk'
  tag fixid: 'F-44812r1_fix'
  tag version: 'WN12-CC-000065'
  tag ruleid: 'SV-51737r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Application Compatibility Diagnostics -> "Detect compatibility issues for applications and drivers" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\AppCompat\

Value Name: DisablePcaUI

Type: REG_DWORD
Value: 0'

# START_DESCRIBE V-36696
  
    describe registry_key({
      name: 'DisablePcaUI',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\AppCompat',
    }) do
      its("DisablePcaUI") { should eq 0 }
    end

# STOP_DESCRIBE V-36696

end

