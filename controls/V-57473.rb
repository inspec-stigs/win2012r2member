# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57473 - The maximum number of error reports to queue on a system must be configured to 50 or greater.'
control 'V-57473' do
  impact 0.5
  title 'The maximum number of error reports to queue on a system must be configured to 50 or greater.'
  desc 'The error reporting queue is stored locally on the system and contains the error reports until they have been manually removed or automatically sent to the local collector or DOD-wide collector (if defined).  Once a report has been sent to a collector, it is moved to the report archive.  Old reports are deleted as new ones arrive once the maximum limit has been met.'
  tag 'stig', 'V-57473'
  tag severity: 'medium'
  tag checkid: 'C-58379r1_chk'
  tag fixid: 'F-62747r1_fix'
  tag version: 'WN12-ER-000015'
  tag ruleid: 'SV-71941r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled" with "Maximum number of reports to queue:" set to "50" or greater.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  MaxQueueCount

Type:  REG_DWORD
Value:  0x00000032 (50)  (or greater)'

# START_DESCRIBE V-57473
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57473

end

