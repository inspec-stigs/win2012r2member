# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57475 - The system must be configured to attempt to forward queued error reports once a day.'
control 'V-57475' do
  impact 0.5
  title 'The system must be configured to attempt to forward queued error reports once a day.'
  desc 'Error reports stored in the queue should be forwarded to a local or DOD-wide collection site when the system can connect to the site.  This setting controls the frequency a system will use to try forwarding queued reports to the local or DOD-wide collector.'
  tag 'stig', 'V-57475'
  tag severity: 'medium'
  tag checkid: 'C-58389r1_chk'
  tag fixid: 'F-62757r1_fix'
  tag version: 'WN12-ER-000016'
  tag ruleid: 'SV-71951r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Queue" to "Enabled" with "Number of days between solution check reminders:" set to "1".'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\

Value Name:  QueuePesterInterval

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-57475
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57475

end

