# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1099 - The lockout duration must be configured to require an administrator to unlock an account.'
control 'V-1099' do
  impact 0.5
  title 'The lockout duration must be configured to require an administrator to unlock an account.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that an account will remain locked after the specified number of failed logon attempts.  A value of 0 will require an administrator to unlock the account.'
  tag 'stig', 'V-1099'
  tag severity: 'medium'
  tag checkid: 'C-47167r2_chk'
  tag fixid: 'F-45776r1_fix'
  tag version: 'WN12-AC-000001'
  tag ruleid: 'SV-52850r1_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy -> "Account lockout duration" to "0" minutes, "Account is locked out until administrator unlocks it".'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy.

If the "Account lockout duration" is not set to "0", requiring an administrator to unlock the account, this is a finding.'

# START_DESCRIBE V-1099
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1099

end

