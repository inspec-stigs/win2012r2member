# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26491 - Unauthorized accounts must not have the Increase a process working set user right.'
control 'V-26491' do
  impact 0.5
  title 'Unauthorized accounts must not have the Increase a process working set user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Increase a process working set" user right can change the size of a processs working set, potentially causing performance issues or a DoS.'
  tag 'stig', 'V-26491'
  tag severity: 'medium'
  tag checkid: 'C-47353r1_chk'
  tag fixid: 'F-45973r1_fix'
  tag version: 'WN12-UR-000026'
  tag ruleid: 'SV-53047r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Increase a process working set" to only include the following accounts or groups:

Administrators
Local Service
Window Manager\Window Manager Group'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Increase a process working set" user right, this is a finding:

Administrators
Local Service
Window Manager\Window Manager Group'

# START_DESCRIBE V-26491
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26491

end

