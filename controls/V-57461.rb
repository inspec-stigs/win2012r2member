# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57461 - The system must be configured to send error reports on TCP port 1232.'
control 'V-57461' do
  impact 0.5
  title 'The system must be configured to send error reports on TCP port 1232.'
  desc 'An error reporting sites TCP port must be defined in the local system in order to forward data from local systems via TCP.  Port 1232 is the recommended port setting.'
  tag 'stig', 'V-57461'
  tag severity: 'medium'
  tag checkid: 'C-58319r1_chk'
  tag fixid: 'F-62679r1_fix'
  tag version: 'WN12-ER-000009'
  tag ruleid: 'SV-71879r1_rule'
  tag fixtext: 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Corporate Windows Error Reporting" to "Enabled" with "1232" defined as the "Server Port".'
  tag checktext: 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  CorporateWerPortNumber

Type:  REG_DWORD
Value:  0x000004d0 (1232)'

# START_DESCRIBE V-57461
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57461

end

