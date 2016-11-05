# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1072 - Shared user accounts must not be permitted on the system.'
control 'V-1072' do
  impact 0.5
  title 'Shared user accounts must not be permitted on the system.'
  desc 'Shared accounts (accounts where two or more people log in with the same user identification) do not provide adequate identification and authentication.  There is no way to provide for nonrepudiation or individual accountability for system access and resource usage.'
  tag 'stig', 'V-1072'
  tag severity: 'medium'
  tag checkid: 'C-47156r2_chk'
  tag fixid: 'F-45765r1_fix'
  tag version: 'WN12-00-000012'
  tag ruleid: 'SV-52839r1_rule'
  tag fixtext: 'Remove any shared accounts from the system.'
  tag checktext: 'Determine whether any shared accounts exist.  If no shared accounts exist, this is NA.
If shared accounts exist, this is a finding.'

# START_DESCRIBE V-1072
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1072

end

