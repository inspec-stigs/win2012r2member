# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15713 - Microsoft Active Protection Service membership must be disabled.'
control 'V-15713' do
  impact 0.5
  title 'Microsoft Active Protection Service membership must be disabled.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this feature will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  This setting disables Microsoft Active Protection Service membership and reporting.'
  tag 'stig', 'V-15713'
  tag severity: 'medium'
  tag checkid: 'C-47440r4_chk'
  tag fixid: 'F-62313r2_fix'
  tag version: 'WN12-CC-000111'
  tag ruleid: 'SV-53134r2_rule'
  tag fixtext: 'Windows 2012 R2:
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender -> MAPS -> "Join Microsoft MAPS" to "Disabled".

Windows 2012:
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender -> "Configure Microsoft Active Protection Service Reporting" to "Disabled".'
  tag checktext: 'If the following registry value exists and is set to "1" (Basic) or "2" (Advanced), this is a finding:

If the registry value does not exist, this is not a finding.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows Defender\SpyNet\

Value Name:  SpyNetReporting

Type:  REG_DWORD
Value:  1 or 2 = a Finding'

# START_DESCRIBE V-15713
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15713

end

