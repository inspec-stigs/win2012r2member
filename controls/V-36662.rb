# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36662 - Application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.'
control 'V-36662' do
  impact 0.5
  title 'Application account passwords must be changed at least annually or when a system administrator with knowledge of the password leaves the organization.'
  desc 'Setting application accounts to expire may cause applications to stop functioning.  However, not changing them on a regular basis  exposes them to attack.'
  tag 'stig', 'V-36662'
  tag severity: 'medium'
  tag checkid: 'C-46843r2_chk'
  tag fixid: 'F-44709r2_fix'
  tag version: 'WN12-00-000011'
  tag ruleid: 'SV-51580r2_rule'
  tag fixtext: 'Change application/service account passwords that are manually managed and entered by a system administrator at least annually or whenever an administrator with knowledge of the password leaves the organization.'
  tag checktext: 'Determine if any system administrators with knowledge of application account passwords have left the organization within the last year.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
PwsdLastSetTime 

If any application accounts listed that are manually managed and have a date older than one year in the "PwsdLastSetTime" column, this is a finding.
If any system administrators with knowledge of application account passwords have left the organization within the last year and the "PwsdLastSetTime" field reflects that application account passwords were not changed at that time, this is a finding.'

# START_DESCRIBE V-36662
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36662

end

