# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26483 - The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.'
control 'V-26483' do
  impact 0.5
  title 'The Deny log on as a batch job user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems, and from unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  The "Deny log on as a batch job" user right defines accounts that are prevented from logging on to the system as a batch job such, as Task Scheduler.    In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.  The Guests group must be assigned to prevent unauthenticated access.'
  tag 'stig', 'V-26483'
  tag severity: 'medium'
  tag checkid: 'C-46807r1_chk'
  tag fixid: 'F-44652r1_fix'
  tag version: 'WN12-UR-000018-MS'
  tag ruleid: 'SV-51502r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a batch job" to include the following:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

All Systems:
Guests Group'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a batch job" user right, this is a finding:

Domain Systems Only:
Enterprise Admins Group
Domain Admins Group

All Systems:
Guests Group'

# START_DESCRIBE V-26483
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26483

end

