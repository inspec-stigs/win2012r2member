# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26477 - Unauthorized accounts must not have the Change the time zone user right.'
control 'V-26477' do
  impact 0.1
  title 'Unauthorized accounts must not have the Change the time zone user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Change the time zone" user right can change the time zone of a system.'
  tag 'stig', 'V-26477'
  tag severity: 'low'
  tag checkid: 'C-47423r1_chk'
  tag fixid: 'F-46043r1_fix'
  tag version: 'WN12-UR-000010'
  tag ruleid: 'SV-53117r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Change the time zone" to only include the following accounts or groups:

Administrators
Local Service'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Change the time zone" user right, this is a finding:

Administrators
Local Service'

# START_DESCRIBE V-26477
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26477

end

