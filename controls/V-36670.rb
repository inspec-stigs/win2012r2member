# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36670 - Audit data must be reviewed on a regular basis.'
control 'V-36670' do
  impact 0.5
  title 'Audit data must be reviewed on a regular basis.'
  desc 'To be of value, audit logs from critical systems must be reviewed on a regular basis.  Critical systems should be reviewed on a daily basis to identify security breaches and potential weaknesses in the security structure.  This can be done with the use of monitoring software or other utilities for this purpose.'
  tag 'stig', 'V-36670'
  tag severity: 'medium'
  tag checkid: 'C-46830r2_chk'
  tag fixid: 'F-44692r2_fix'
  tag version: 'WN12-AU-000200'
  tag ruleid: 'SV-51561r1_rule'
  tag fixtext: 'Review audit logs on a predetermined scheduled.'
  tag checktext: 'Determine whether audit logs are reviewed on a predetermined schedule.  If audit logs are not reviewed on a regular basis, this is a finding.'

# START_DESCRIBE V-36670
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36670

end

