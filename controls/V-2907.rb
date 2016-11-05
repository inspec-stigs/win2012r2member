# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-2907 - System files must be monitored for unauthorized changes.'
control 'V-2907' do
  impact 0.5
  title 'System files must be monitored for unauthorized changes.'
  desc 'Monitoring system files for changes against a baseline on a regular basis may help detect the possible introduction of malicious code on a system.'
  tag 'stig', 'V-2907'
  tag severity: 'medium'
  tag checkid: 'C-46961r1_chk'
  tag fixid: 'F-45234r1_fix'
  tag version: 'WN12-GE-000017'
  tag ruleid: 'SV-52215r2_rule'
  tag fixtext: 'Monitor system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis.  This can be done with the use of various monitoring tools.'
  tag checktext: 'Determine whether the site monitors system files (e.g., *.exe, *.bat, *.com, *.cmd, and *.dll) on servers for unauthorized changes against a baseline on a weekly basis.  If system files are not monitored for unauthorized changes, this is a finding.

A properly configured HBSS Policy Auditor 5.2 or later File Integrity Monitor (FIM) module will meet the requirement for file integrity checking. The Asset module within HBSS does not meet this requirement.'

# START_DESCRIBE V-2907
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-2907

end

