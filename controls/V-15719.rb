# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15719 - Users must be notified if the logon server was inaccessible and cached credentials were used.'
control 'V-15719' do
  impact 0.1
  title 'Users must be notified if the logon server was inaccessible and cached credentials were used.'
  desc 'Notifying a user whether cached credentials were used may make them aware of connection issues.'
  tag 'stig', 'V-15719'
  tag severity: 'low'
  tag checkid: 'C-61745r2_chk'
  tag fixid: 'F-66509r2_fix'
  tag version: 'WN12-CC-000119'
  tag ruleid: 'SV-53138r3_rule'
  tag fixtext: 'If the system is not a member of a domain, this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Logon Options >> "Report when logon server was not available during user logon" to "Enabled".'
  tag checktext: 'If the system is not a member of a domain, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\

Value Name:  ReportControllerMissing

Type:  REG_DWORD
Value:  1'

# START_DESCRIBE V-15719
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15719

end

