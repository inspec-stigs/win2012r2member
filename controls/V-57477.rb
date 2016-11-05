# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57477 - The system must be configured to automatically consent to send all data requested by a local or DOD-wide error collection site.'
control 'V-57477' do
  impact 0.5
  title 'The system must be configured to automatically consent to send all data requested by a local or DOD-wide error collection site.'
  desc 'Configuring error reporting to send all requested data ensures all relevant data associated with the error report is captured for later analysis.  This setting determines the default consent behavior of Windows Error Reporting.'
  tag 'stig', 'V-57477'
  tag severity: 'medium'
  tag checkid: 'C-58399r1_chk'
  tag fixid: 'F-62767r1_fix'
  tag version: 'WN12-ER-000017'
  tag ruleid: 'SV-71961r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Consent -> "Configure Default consent" to "Enabled" with "Send all data" selected for "Consent level".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent\

Value Name:  DefaultConsent

Type:  REG_DWORD
Value:  0x00000004 (4)'

# START_DESCRIBE V-57477
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57477

end

