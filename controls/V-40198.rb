# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40198 - Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'
control 'V-40198' do
  impact 0.5
  title 'Members of the Backup Operators group must have separate accounts for backup duties and normal operational tasks.'
  desc 'Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk drives for backup and restore purposes.  Members of the Backup Operators group must have separate logon accounts for performing backup duties.'
  tag 'stig', 'V-40198'
  tag severity: 'medium'
  tag checkid: 'C-46952r1_chk'
  tag fixid: 'F-45183r1_fix'
  tag version: 'WN12-00-000009-02'
  tag ruleid: 'SV-52157r2_rule'
  tag fixtext: 'Ensure each member of the Backup Operators group has separate accounts for backup functions and standard user functions.'
  tag checktext: 'If no accounts are members of the Backup Operators group, this is NA.

Verify users with accounts in the Backup Operators group have a separate user account for backup functions and for performing normal user tasks.  If users with accounts in the Backup Operators group do not have separate accounts for backup functions and standard user functions, this is a finding.'

# START_DESCRIBE V-40198
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40198

end

