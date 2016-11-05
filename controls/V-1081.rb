# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1081 - Local volumes must be formatted using NTFS.'
control 'V-1081' do
  impact 1.0
  title 'Local volumes must be formatted using NTFS.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system.  To support this, volumes must be formatted using the NTFS file system.'
  tag 'stig', 'V-1081'
  tag severity: 'high'
  tag checkid: 'C-47160r3_chk'
  tag fixid: 'F-45769r1_fix'
  tag version: 'WN12-GE-000005'
  tag ruleid: 'SV-52843r2_rule'
  tag fixtext: 'Format all partitions/drives to use NTFS.'
  tag checktext: 'Open the Computer Management Console.
Expand the "Storage" object in the Tree window.
Select the "Disk Management" object.

If the file system column does not indicate "NTFS" as the file system for each local hard drive, this is a finding.

Some hardware vendors create a small FAT partition to store troubleshooting and recovery data. No other files must be stored here.  This must be documented with the ISSO.'

# START_DESCRIBE V-1081
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1081

end

