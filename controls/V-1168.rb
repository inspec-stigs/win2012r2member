# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1168 - Members of the Backup Operators group must be documented.'
control 'V-1168' do
  impact 0.5
  title 'Members of the Backup Operators group must be documented.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes.  Visibility of members of the Backup Operators group must be maintained.'
  tag 'stig', 'V-1168'
  tag severity: 'medium'
  tag checkid: 'C-46951r2_chk'
  tag fixid: 'F-45181r1_fix'
  tag version: 'WN12-00-000009-01'
  tag ruleid: 'SV-52156r2_rule'
  tag fixtext: 'Create the necessary documentation that identifies the members of the Backup Operators group.'
  tag checktext: 'If no accounts are members of the Backup Operators group, this is NA.

Any accounts that are members of the Backup Operators group, including application accounts, must be documented with the ISSO.  If documentation of accounts that are members of the Backup Operators group is not maintained this is a finding.'

# START_DESCRIBE V-1168
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1168

end

