# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57471 - The system must be configured to add all error reports to the queue.'
control 'V-57471' do
  impact 0.5
  title 'The system must be configured to add all error reports to the queue.'
  desc 'Error reports are queued for sending to an error reporting site when the queueing behavior is set to Always Queue.  This will maintain the reports in the queue until a connection can be made to the collection server.'
  tag 'stig', 'V-57471'
  tag severity: 'medium'
  tag checkid: 'C-58369r1_chk'
  tag fixid: 'F-62737r1_fix'
  tag version: 'WN12-ER-000014'
  tag ruleid: 'SV-71931r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled" with "Queuing behavior:" to "Always queue".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  ForceQueue

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-57471
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57471

end

