# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26506 - Unauthorized accounts must not have the Take ownership of files or other objects user right.'
control 'V-26506' do
  impact 0.5
  title 'Unauthorized accounts must not have the Take ownership of files or other objects user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Take ownership of files or other objects" user right can take ownership of objects and make changes.'
  tag 'stig', 'V-26506'
  tag severity: 'medium'
  tag checkid: 'C-46941r1_chk'
  tag fixid: 'F-45148r1_fix'
  tag version: 'WN12-UR-000042'
  tag ruleid: 'SV-52123r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Take ownership of files or other objects" to only include the following accounts or groups:

Administrators'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Take ownership of files or other objects" user right, this is a finding:

Administrators'

# START_DESCRIBE V-26506
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26506

end

