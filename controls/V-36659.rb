# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36659 - Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'
control 'V-36659' do
  impact 1.0
  title 'Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.'
  tag 'stig', 'V-36659'
  tag severity: 'high'
  tag checkid: 'C-46839r2_chk'
  tag fixid: 'F-44705r1_fix'
  tag version: 'WN12-00-000005'
  tag ruleid: 'SV-51576r1_rule'
  tag fixtext: 'Ensure each user with administrative privileges has a separate account for user duties and one for privileged duties.'
  tag checktext: 'Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.'

# START_DESCRIBE V-36659
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36659

end

