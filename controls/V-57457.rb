# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57457 - The system must be configured to store error reports locally, on the system or in the enclave, and not send them to Microsoft.'
control 'V-57457' do
  impact 0.5
  title 'The system must be configured to store error reports locally, on the system or in the enclave, and not send them to Microsoft.'
  desc 'Forwarding error reports to vendors could expose sensitive information.  This setting controls the configuration of a local or DOD-wide error reporting site.   In order to not send the data to any system at this time, yet create the reports locally on the system, this value needs to be a single blank character.  To forward error reports to a collection server, the sites error reporting server name or IP address must be defined.'
  tag 'stig', 'V-57457'
  tag severity: 'medium'
  tag checkid: 'C-58291r1_chk'
  tag fixid: 'F-62651r1_fix'
  tag version: 'WN12-ER-000007'
  tag ruleid: 'SV-71859r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Corporate Windows Error Reporting" -> to "Enabled" with "Corporate server name:" defined as a single blank character to store the data on the system or the name or IP address of the local collection server.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  CorporateWerServer

Type:  REG_SZ
Value:  " "       (A single BLANK character to store the data on the system or the error reporting server name or IP address to forward the data to.)'

# START_DESCRIBE V-57457
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57457

end

