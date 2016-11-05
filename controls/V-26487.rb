# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26487 - Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on member servers.'
control 'V-26487' do
  impact 0.5
  title 'Unauthorized accounts must not have the Enable computer and user accounts to be trusted for delegation user right on member servers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed.  This could potentially allow unauthorized users to impersonate other users.'
  tag 'stig', 'V-26487'
  tag severity: 'medium'
  tag checkid: 'C-46805r1_chk'
  tag fixid: 'F-44649r1_fix'
  tag version: 'WN12-UR-000022-MS'
  tag ruleid: 'SV-51500r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank).'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.'

# START_DESCRIBE V-26487
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26487

end

