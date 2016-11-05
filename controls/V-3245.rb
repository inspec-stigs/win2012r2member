# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3245 - File shares must limit access to data on a system.'
control 'V-3245' do
  impact 0.5
  title 'File shares must limit access to data on a system.'
  desc 'Shares on a system provide network access.  To prevent exposing sensitive information, where shares are necessary, permissions must be reconfigured to give the minimum access to those accounts that require it.'
  tag 'stig', 'V-3245'
  tag severity: 'medium'
  tag checkid: 'C-47198r3_chk'
  tag fixid: 'F-45807r2_fix'
  tag version: 'WN12-GE-000018'
  tag ruleid: 'SV-52881r2_rule'
  tag fixtext: 'If a share is required on a system, configure the share and NTFS permissions to limit access to the specific groups or accounts that require it.

Remove any unnecessary nonsystem-created shares.'
  tag checktext: 'Open "Computer Management".
Navigate to "Shared Folders" under "System Tools".
Select the "Shares" object.
Right click any non-system-created shares (the system will prompt when Properties is selected for system-created shares).
Select Properties.
Select the Share Permissions tab.

Verify the necessity of any shares found.  If the file shares have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.

Select the Security tab.

If the NTFS permissions have not been reconfigured to restrict permissions to the specific groups or accounts that require access, this is a finding.'

# START_DESCRIBE V-3245
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-3245

end

