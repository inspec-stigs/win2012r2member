# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57469 - The system must be configured to queue error reports until a local or DOD-wide collector is available.'
control 'V-57469' do
  impact 0.5
  title 'The system must be configured to queue error reports until a local or DOD-wide collector is available.'
  desc 'Queueing error reports provides the ability for a system to collect reports locally or until a collection server can be contacted.  Valuable system diagnostic and vulnerability information may be lost if the report queue is disabled.'
  tag 'stig', 'V-57469'
  tag severity: 'medium'
  tag checkid: 'C-58359r1_chk'
  tag fixid: 'F-62727r1_fix'
  tag version: 'WN12-ER-000013'
  tag ruleid: 'SV-71921r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  DisableQueue

Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-57469
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57469

end

