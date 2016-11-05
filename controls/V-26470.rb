# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26470 - Unauthorized accounts must not have the Access this computer from the network user right on member servers.'
control 'V-26470' do
  impact 0.5
  title 'Unauthorized accounts must not have the Access this computer from the network user right on member servers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Access this computer from the network" user right may access resources on the system, and must be limited to those that require it.'
  tag 'stig', 'V-26470'
  tag severity: 'medium'
  tag checkid: 'C-49426r2_chk'
  tag fixid: 'F-49518r2_fix'
  tag version: 'WN12-UR-000002-MS'
  tag ruleid: 'SV-51499r3_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Access this computer from the network" to only include the following accounts or groups:

Administrators
Authenticated Users

Systems dedicated to managing Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG), must only allow Administrators, removing the Authenticated Users group.'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Access this computer from the network" user right, this is a finding:

Administrators
Authenticated Users

Systems dedicated to managing Active Directory (AD admin platforms, see V-36436 in the Active Directory Domain STIG), must only allow Administrators, removing the Authenticated Users group.'

# START_DESCRIBE V-26470
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26470

end

