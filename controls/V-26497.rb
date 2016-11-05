# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26497 - Unauthorized accounts must not have the Modify an object label user right.'
control 'V-26497' do
  impact 0.5
  title 'Unauthorized accounts must not have the Modify an object label user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  Accounts with the "Modify an object label" user right can change the integrity label of an object.  This could potentially be used to execute code at a higher privilege.'
  tag 'stig', 'V-26497'
  tag severity: 'medium'
  tag checkid: 'C-47338r1_chk'
  tag fixid: 'F-45958r1_fix'
  tag version: 'WN12-UR-000033'
  tag ruleid: 'SV-53033r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Modify an object label" to be defined but containing no entries (blank).'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are granted the "Modify an object label" user right, this is a finding.'

# START_DESCRIBE V-26497
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26497

end

