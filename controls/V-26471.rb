# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26471 - Unauthorized accounts must not have the Adjust memory quotas for a process user right.'
control 'V-26471' do
  impact 0.5
  title 'Unauthorized accounts must not have the Adjust memory quotas for a process user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Adjust memory quotas for a process" user right can adjust memory that is available to processes, and could be used in a denial of service (DoS) attack.'
  tag 'stig', 'V-26471'
  tag severity: 'medium'
  tag checkid: 'C-46926r1_chk'
  tag fixid: 'F-45134r1_fix'
  tag version: 'WN12-UR-000004'
  tag ruleid: 'SV-52109r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Adjust memory quotas for a process" to only include the following accounts or groups:

Administrators
Local Service
Network Service'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Adjust memory quotas for a process" user right, this is a finding:

Administrators
Local Service
Network Service'

# START_DESCRIBE V-26471
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26471

end

