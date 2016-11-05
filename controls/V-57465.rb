# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57465 - The system must be configured to store all data in the error report archive.'
control 'V-57465' do
  impact 0.5
  title 'The system must be configured to store all data in the error report archive.'
  desc 'The error reporting archive is stored locally on the system and is created after an error report has been sent to the local collector or DOD-wide collector (if defined).  Storing all data, including memory contents, adds data that is very helpful in analyzing the errors.'
  tag 'stig', 'V-57465'
  tag severity: 'medium'
  tag checkid: 'C-58339r1_chk'
  tag fixid: 'F-62707r1_fix'
  tag version: 'WN12-ER-000011'
  tag ruleid: 'SV-71899r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Archive" to "Enabled" with "Store All" selected for "Archive behavior:".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  ConfigureArchive

Type:  REG_DWORD
Value:  0x00000002 (2)'

# START_DESCRIBE V-57465
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57465

end

