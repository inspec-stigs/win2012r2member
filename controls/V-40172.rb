# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40172 - Backups of system-level information must be protected.'
control 'V-40172' do
  impact 0.1
  title 'Backups of system-level information must be protected.'
  desc 'A system backup will usually include sensitive information such as user accounts that could be used in an attack.  As a valuable system resource, the system backup must be protected and stored in a physically secure location.'
  tag 'stig', 'V-40172'
  tag severity: 'low'
  tag checkid: 'C-46943r1_chk'
  tag fixid: 'F-45156r1_fix'
  tag version: 'WN12-00-000016'
  tag ruleid: 'SV-52130r2_rule'
  tag fixtext: 'Ensure system-level information backups are stored in a secure location and protected from destruction.'
  tag checktext: 'Determine if system-level information backups are protected from destruction and stored in a physically secure location.  If they are not, this is a finding.'

# START_DESCRIBE V-40172
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40172

end

