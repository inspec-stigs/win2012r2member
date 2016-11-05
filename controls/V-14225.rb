# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-14225 - Passwords for the built-in Administrator account must be changed at least annually or when a member of the administrative team leaves the organization.'
control 'V-14225' do
  impact 0.5
  title 'Passwords for the built-in Administrator account must be changed at least annually or when a member of the administrative team leaves the organization.'
  desc 'The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the password.   Passwords for the built-in Administrator account must be changed at least annually or when any member of the administrative team leaves the organization.'
  tag 'stig', 'V-14225'
  tag severity: 'medium'
  tag checkid: 'C-47248r2_chk'
  tag fixid: 'F-45868r1_fix'
  tag version: 'WN12-00-000007'
  tag ruleid: 'SV-52942r2_rule'
  tag fixtext: 'Change the built-in Administrator account password at least annually or whenever an administrator leaves the organization.'
  tag checktext: 'Determine if any system administrators have left the organization within the last year.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
PwsdLastSetTime 

If the built-in Administrator account has a date older than one year in the "PwsdLastSetTime" column, this is a finding.
If any system administrators has left the organization within the last year and the "PwsdLastSetTime" field reflects the built-in Administrator account password was not changed at that time, this is a finding.'

# START_DESCRIBE V-14225
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-14225

end

