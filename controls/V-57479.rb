# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57479 - The system must be configured to permit the default consent levels of Windows Error Reporting to override any other consent policy setting.'
control 'V-57479' do
  impact 0.5
  title 'The system must be configured to permit the default consent levels of Windows Error Reporting to override any other consent policy setting.'
  desc 'This setting determines the behavior of the "Configure Default Consent" setting in relation to custom consent settings.  Enabling this allows the default consent levels of Windows Error Reporting to always override any other consent policy setting.'
  tag 'stig', 'V-57479'
  tag severity: 'medium'
  tag checkid: 'C-58409r1_chk'
  tag fixid: 'F-62777r1_fix'
  tag version: 'WN12-ER-000018'
  tag ruleid: 'SV-71971r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Consent -> "Ignore custom consent settings" to "Enabled".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent\

Value Name:  DefaultOverrideBehavior

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-57479
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57479

end

