# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26479 - Unauthorized accounts must not have the Create a token object user right.'
control 'V-26479' do
  impact 1.0
  title 'Unauthorized accounts must not have the Create a token object user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  The "Create a token object" user right allows a process to create an access token. This could be used to provide elevated rights and compromise a system.'
  tag 'stig', 'V-26479'
  tag severity: 'high'
  tag checkid: 'C-46930r1_chk'
  tag fixid: 'F-45138r1_fix'
  tag version: 'WN12-UR-000012'
  tag ruleid: 'SV-52113r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Create a token object" to be defined but containing no entries (blank).'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Create a token object" user right, this is a finding.'

# START_DESCRIBE V-26479
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26479

end

