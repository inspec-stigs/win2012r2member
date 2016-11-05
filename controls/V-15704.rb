# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15704 - Errors in handwriting recognition on tablet PCs must not be reported to Microsoft.'
control 'V-15704' do
  impact 0.1
  title 'Errors in handwriting recognition on tablet PCs must not be reported to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.   This setting prevents errors in handwriting recognition on tablet PCs from being reported to Microsoft.'
  tag 'stig', 'V-15704'
  tag severity: 'low'
  tag checkid: 'C-47422r2_chk'
  tag fixid: 'F-46042r1_fix'
  tag version: 'WN12-CC-000035'
  tag ruleid: 'SV-53116r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off handwriting recognition error reporting" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Microsoft\Windows\HandwritingErrorReports\

Value Name: PreventHandwritingErrorReports

Type: REG_DWORD
Value: 1'

# START_DESCRIBE V-15704
  
    describe registry_key({
      name: 'PreventHandwritingErrorReports',
      hive: 'HKEY_LOCAL_MACHINE',
      key:  'Software\Policies\Microsoft\Windows\HandwritingErrorReports',
    }) do
      its("PreventHandwritingErrorReports") { should eq 1 }
    end

# STOP_DESCRIBE V-15704

end

