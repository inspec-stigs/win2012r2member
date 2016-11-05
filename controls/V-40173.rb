# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40173 - System-related documentation must be backed up in accordance with local recovery time and recovery point objectives.'
control 'V-40173' do
  impact 0.1
  title 'System-related documentation must be backed up in accordance with local recovery time and recovery point objectives.'
  desc 'Operating system backup is a critical step in maintaining data assurance and availability.   Information system and security-related documentation contains information pertaining to system configuration and security settings.   Backups shall be consistent with organizational recovery time and recovery point objectives.'
  tag 'stig', 'V-40173'
  tag severity: 'low'
  tag checkid: 'C-58963r1_chk'
  tag fixid: 'F-63427r1_fix'
  tag version: 'WN12-00-000017'
  tag ruleid: 'SV-52131r3_rule'
  tag fixtext: 'Back up system-related documentation in accordance with local recovery time and recovery point objectives.'
  tag checktext: 'Determine whether system-related documentation is backed up in accordance with local recovery time and recovery point objectives.  If system-related documentation is not backed up in accordance with local recovery time and recovery point objectives, this is a finding.'

# START_DESCRIBE V-40173
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40173

end

