# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26476 - Unauthorized accounts must not have the Change the system time user right.'
control 'V-26476' do
  impact 0.5
  title 'Unauthorized accounts must not have the Change the system time user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Change the system time" user right can change the system time, which can impact authentication, as well as affect time stamps on event log entries.'
  tag 'stig', 'V-26476'
  tag severity: 'medium'
  tag checkid: 'C-47424r1_chk'
  tag fixid: 'F-46044r1_fix'
  tag version: 'WN12-UR-000009'
  tag ruleid: 'SV-53118r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Change the system time" to only include the following accounts or groups:

Administrators
Local Service'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Change the system time" user right, this is a finding:

Administrators
Local Service'

# START_DESCRIBE V-26476
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26476

end

