# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26490 - Unauthorized accounts must not have the Impersonate a client after authentication user right.'
control 'V-26490' do
  impact 0.5
  title 'Unauthorized accounts must not have the Impersonate a client after authentication user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.  The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf.  An attacker could potentially use this to elevate privileges.'
  tag 'stig', 'V-26490'
  tag severity: 'medium'
  tag checkid: 'C-46934r1_chk'
  tag fixid: 'F-45142r1_fix'
  tag version: 'WN12-UR-000025'
  tag ruleid: 'SV-52117r2_rule'
  tag fixtext: 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Impersonate a client after authentication" to only include the following accounts or groups:

Administrators
Service
Local Service
Network Service'
  tag checktext: 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Impersonate a client after authentication" user right, this is a finding:

Administrators
Service
Local Service
Network Service'

# START_DESCRIBE V-26490
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26490

end

