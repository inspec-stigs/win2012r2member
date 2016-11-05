# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36658 - Users with administrative privilege must be documented.'
control 'V-36658' do
  impact 0.5
  title 'Users with administrative privilege must be documented.'
  desc 'Administrative accounts may perform any action on a system.  Users with administrative accounts must be documented to ensure those with this level of access are clearly identified.'
  tag 'stig', 'V-36658'
  tag severity: 'medium'
  tag checkid: 'C-46838r2_chk'
  tag fixid: 'F-44704r1_fix'
  tag version: 'WN12-00-000004'
  tag ruleid: 'SV-51575r2_rule'
  tag fixtext: 'Create the necessary documentation that identifies the members of the Administrators group.'
  tag checktext: 'Review the necessary documentation that identifies the members of the Administrators group.  If a list of all users belonging to the Administrators group is not maintained with the ISSO, this is a finding.'

# START_DESCRIBE V-36658
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36658

end

