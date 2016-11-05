# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57453 - The system must be configured to collect multiple error reports of the same event type.'
control 'V-57453' do
  impact 0.5
  title 'The system must be configured to collect multiple error reports of the same event type.'
  desc 'Multiple error reports of the same error type are useful in diagnosing potential system configuration issues, as well as intrusion activity.  This setting controls whether error reporting collects additional, second-level report data even if a CAB file containing data about the event types has already been collected.'
  tag 'stig', 'V-57453'
  tag severity: 'medium'
  tag checkid: 'C-58277r1_chk'
  tag fixid: 'F-62637r1_fix'
  tag version: 'WN12-ER-000005'
  tag ruleid: 'SV-71847r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Do not throttle additional data" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  BypassDataThrottling

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-57453
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57453

end

