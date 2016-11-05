# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26475 - Unauthorized accounts must not have the Bypass traverse checking user right.'
control 'V-26475' do
  impact 0.1
  title 'Unauthorized accounts must not have the Bypass traverse checking user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Bypass traverse checking" user right can pass through folders when browsing even if they do not have the "Traverse Folder" access permission. They could potentially view sensitive file and folder names.  They would not have additional access to the files and folders unless it is granted through permissions.'
  tag 'stig', 'V-26475'
  tag severity: 'low'
  tag checkid: 'C-46929r1_chk'
  tag fixid: 'F-45137r1_fix'
  tag version: 'WN12-UR-000008'
  tag ruleid: 'SV-52112r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Bypass traverse checking" to only include the following accounts or groups:

Administrators
Authenticated Users
Local Service
Network Service
Window Manager\Window Manager Group'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Bypass traverse checking" user right, this is a finding:

Administrators
Authenticated Users
Local Service
Network Service
Window Manager\Window Manager Group'

# START_DESCRIBE V-26475
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26475

end

