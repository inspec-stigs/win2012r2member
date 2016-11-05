# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15714 - The system must be configured to save Error Reporting events and messages to the system event log.'
control 'V-15714' do
  impact 0.5
  title 'The system must be configured to save Error Reporting events and messages to the system event log.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  This setting ensures that Error Reporting events will be saved in the system event log.'
  tag 'stig', 'V-15714'
  tag severity: 'medium'
  tag checkid: 'C-47441r3_chk'
  tag fixid: 'F-46061r3_fix'
  tag version: 'WN12-ER-000003'
  tag ruleid: 'SV-53135r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Disable logging" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  LoggingDisabled

Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-15714
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15714

end

