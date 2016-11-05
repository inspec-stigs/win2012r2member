# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36672 - Audit records must be backed up onto a different system or media than the system being audited.'
control 'V-36672' do
  impact 0.5
  title 'Audit records must be backed up onto a different system or media than the system being audited.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted.  Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  tag 'stig', 'V-36672'
  tag severity: 'medium'
  tag checkid: 'C-58509r2_chk'
  tag fixid: 'F-62923r1_fix'
  tag version: 'WN12-AU-000203-01'
  tag ruleid: 'SV-51566r2_rule'
  tag fixtext: 'Establish and implement a process for backing up log data to another system or media other than the system being audited.'
  tag checktext: 'Determine if a process to back up log data to a different system or media than the system being audited has been implemented.  If it has not, this is a finding.'

# START_DESCRIBE V-36672
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36672

end

