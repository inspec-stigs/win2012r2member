# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15715 - The system must be configured to generate error reports.'
control 'V-15715' do
  impact 0.5
  title 'The system must be configured to generate error reports.'
  desc 'Enabling Windows Error Reporting generates information useful to system administrators and forensics analysts for diagnosing system problems and investigating intrusions.  If Windows Error Reporting is turned off, valuable system diagnostic and vulnerability information may be lost.'
  tag 'stig', 'V-15715'
  tag severity: 'medium'
  tag checkid: 'C-58139r1_chk'
  tag fixid: 'F-62501r1_fix'
  tag version: 'WN12-ER-000002'
  tag ruleid: 'SV-71721r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Disable Windows Error Reporting" to "Disabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  Disabled

Type:  REG_DWORD
Value:  0'

# START_DESCRIBE V-15715
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15715

end

