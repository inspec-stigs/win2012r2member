# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26503 - Unauthorized accounts must not have the Replace a process level token user right.'
control 'V-26503' do
  impact 0.5
  title 'Unauthorized accounts must not have the Replace a process level token user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  The "Replace a process level token" user right allows one process or service to start another process or service with a different security access token.  A user with this right could use this to impersonate another account.'
  tag 'stig', 'V-26503'
  tag severity: 'medium'
  tag checkid: 'C-46939r1_chk'
  tag fixid: 'F-45146r1_fix'
  tag version: 'WN12-UR-000039'
  tag ruleid: 'SV-52121r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Replace a process level token" to only include the following accounts or groups:

Local Service
Network Service'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Replace a process level token" user right, this is a finding:

Local Service
Network Service'

# START_DESCRIBE V-26503
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26503

end

