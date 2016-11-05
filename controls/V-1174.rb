# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1174 - The amount of idle time required before suspending a session must be properly set.'
control 'V-1174' do
  impact 0.1
  title 'The amount of idle time required before suspending a session must be properly set.'
  desc 'Open sessions can increase the avenues of attack on a system.  This setting is used to control when a computer disconnects an inactive SMB session.  If client activity resumes, the session is automatically reestablished.  This protects critical and sensitive network data from exposure to unauthorized personnel with physical access to the computer.'
  tag 'stig', 'V-1174'
  tag severity: 'low'
  tag checkid: 'C-47195r3_chk'
  tag fixid: 'F-45804r2_fix'
  tag version: 'WN12-SO-000031'
  tag ruleid: 'SV-52878r3_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Microsoft Network Server: Amount of idle time required before suspending session" to "15" minutes or less.'
  tag checktext: 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\

Value Name:  autodisconnect

Value Type:  REG_DWORD
Value:  0x0000000f (15) (or less)'

# START_DESCRIBE V-1174
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1174

end

