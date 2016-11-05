# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57455 - The system must be configured to prevent the display of error messages to the user.'
control 'V-57455' do
  impact 0.5
  title 'The system must be configured to prevent the display of error messages to the user.'
  desc 'Displaying error messages to users provides them the option of sending the reports.  Error reports should be sent silently, unknown to the user.  This setting controls whether users are shown an error dialog box that lets them report an error.'
  tag 'stig', 'V-57455'
  tag severity: 'medium'
  tag checkid: 'C-58289r1_chk'
  tag fixid: 'F-62649r1_fix'
  tag version: 'WN12-ER-000006'
  tag ruleid: 'SV-71851r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Prevent display of the user interface for critical errors" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  DontShowUI

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-57455
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57455

end

