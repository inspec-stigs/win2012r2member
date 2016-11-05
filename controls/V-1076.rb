# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1076 - System-level information must be backed up in accordance with local recovery time and recovery point objectives.'
control 'V-1076' do
  impact 0.1
  title 'System-level information must be backed up in accordance with local recovery time and recovery point objectives.'
  desc 'Operating system backup is a critical step in maintaining data assurance and availability.   System-level information includes system-state information, operating system and application software, and licenses.   Backups must be consistent with organizational recovery time and recovery point objectives.'
  tag 'stig', 'V-1076'
  tag severity: 'low'
  tag checkid: 'C-58957r1_chk'
  tag fixid: 'F-63413r2_fix'
  tag version: 'WN12-00-000014'
  tag ruleid: 'SV-52841r2_rule'
  tag fixtext: 'Implement system-level information backups in accordance with local recovery time and recovery point objectives.'
  tag checktext: 'Determine whether system-level information is backed up in accordance with local recovery time and recovery point objectives.  If system-level information is not backed up in accordance with local recovery time and recovery point objectives, this is a finding.'

# START_DESCRIBE V-1076
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1076

end

