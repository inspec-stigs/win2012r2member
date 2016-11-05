# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36671 - Audit data must be retained for at least one year.'
control 'V-36671' do
  impact 0.5
  title 'Audit data must be retained for at least one year.'
  desc 'Audit records are essential for investigating system activity after the fact.  Retention periods for audit data are determined based on the sensitivity of the data handled by the system.'
  tag 'stig', 'V-36671'
  tag severity: 'medium'
  tag checkid: 'C-46831r2_chk'
  tag fixid: 'F-44693r2_fix'
  tag version: 'WN12-AU-000201'
  tag ruleid: 'SV-51563r1_rule'
  tag fixtext: 'Ensure the audit data is retained for at least a year.'
  tag checktext: 'Determine whether audit data is retained for at least one year.  If the audit data is not retained for at least a year, this is a finding.'

# START_DESCRIBE V-36671
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36671

end

