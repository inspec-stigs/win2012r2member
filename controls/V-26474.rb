# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26474 - Unauthorized accounts must not have the back up files and directories user right.'
control 'V-26474' do
  impact 0.5
  title 'Unauthorized accounts must not have the back up files and directories user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Back up files and directories" user right can circumvent file and directory permissions and could allow access to sensitive data.'
  tag 'stig', 'V-26474'
  tag severity: 'medium'
  tag checkid: 'C-46928r1_chk'
  tag fixid: 'F-45136r1_fix'
  tag version: 'WN12-UR-000007'
  tag ruleid: 'SV-52111r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Back up files and directories" to only include the following accounts or groups:

Administrators'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Back up files and directories" user right, this is a finding:

Administrators'

# START_DESCRIBE V-26474
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26474

end

