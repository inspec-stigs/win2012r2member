# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26482 - Unauthorized accounts must not have the Create symbolic links user right.'
control 'V-26482' do
  impact 0.5
  title 'Unauthorized accounts must not have the Create symbolic links user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Create symbolic links" user right can create pointers to other objects, which could potentially expose the system to attack.'
  tag 'stig', 'V-26482'
  tag severity: 'medium'
  tag checkid: 'C-61747r1_chk'
  tag fixid: 'F-66511r1_fix'
  tag version: 'WN12-UR-000015'
  tag ruleid: 'SV-53054r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create symbolic links" to only include the following accounts or groups:

Administrators

Systems that have the Hyper-V role will also have "Virtual Machines" given this user right.  If this needs to be added manually, enter it as "NT Virtual Machine\Virtual Machines".'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create symbolic links" user right, this is a finding:

Administrators

Systems that have the Hyper-V role will also have "Virtual Machines" given this user right (this may be displayed as "NT Virtual Machine\Virtual Machines").  This is not a finding.'

# START_DESCRIBE V-26482
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26482

end

