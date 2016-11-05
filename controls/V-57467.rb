# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57467 - The maximum number of error reports to archive on a system must be configured to 100 or greater.'
control 'V-57467' do
  impact 0.5
  title 'The maximum number of error reports to archive on a system must be configured to 100 or greater.'
  desc 'The retention of archived reports provides a history.  Older reports are automatically deleted as new reports are generated once the maximum limit has been met.  The archive is stored locally on the system and is created after the error report has been sent to the local collector or DOD-wide collector (if defined).'
  tag 'stig', 'V-57467'
  tag severity: 'medium'
  tag checkid: 'C-58349r1_chk'
  tag fixid: 'F-62717r1_fix'
  tag version: 'WN12-ER-000012'
  tag ruleid: 'SV-71909r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Archive" to "Enabled" with "Maximum number of reports to store:" set to "100" or greater.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  MaxArchiveCount

Type:  REG_DWORD
Value:  0x00000064 (100)  (or greater)'

# START_DESCRIBE V-57467
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57467

end

