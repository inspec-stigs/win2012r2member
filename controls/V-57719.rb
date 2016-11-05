# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57719 - The operating system must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.'
control 'V-57719' do
  impact 0.5
  title 'The operating system must, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.'
  desc 'Protection of log data includes assuring the log data is not accidentally lost or deleted.  Audit information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  tag 'stig', 'V-57719'
  tag severity: 'medium'
  tag checkid: 'C-58511r2_chk'
  tag fixid: 'F-62925r1_fix'
  tag version: 'WN12-AU-000203-02'
  tag ruleid: 'SV-72133r1_rule'
  tag fixtext: 'Configure the operating system to, at a minimum, off-load audit records of interconnected systems in real time and off-load standalone systems weekly.'
  tag checktext: 'Verify the operating system, at a minimum, off-loads audit records of interconnected systems in real time and off-loads standalone systems weekly.  If it does not, this is a finding.'

# START_DESCRIBE V-57719
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57719

end

