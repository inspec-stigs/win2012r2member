# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57459 - The system must be configured to use SSL to forward error reports.'
control 'V-57459' do
  impact 0.5
  title 'The system must be configured to use SSL to forward error reports.'
  desc 'The use of SSL enables the secure forwarding of error reporting data from local systems to a reporting site.'
  tag 'stig', 'V-57459'
  tag severity: 'medium'
  tag checkid: 'C-58309r1_chk'
  tag fixid: 'F-62669r1_fix'
  tag version: 'WN12-ER-000008'
  tag ruleid: 'SV-71869r1_rule'
  tag fixtext: 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Corporate Windows Error Reporting" to "Enabled" with "Connect using SSL" selected.'
  tag checktext: 'This requirement is NA if Windows Error Reporting is not configured to forward reports to a collection server (see V-57457).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  CorporateWerUseSSL

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-57459
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57459

end

