# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-7002 - Accounts must require passwords.'
control 'V-7002' do
  impact 1.0
  title 'Accounts must require passwords.'
  desc 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources.  Accounts on a system must require passwords.'
  tag 'stig', 'V-7002'
  tag severity: 'high'
  tag checkid: 'C-47246r2_chk'
  tag fixid: 'F-45866r2_fix'
  tag version: 'WN12-GE-000015'
  tag ruleid: 'SV-52940r1_rule'
  tag fixtext: 'Ensure all accounts are configured to require passwords to gain access.

The password required flag can be set by entering the following on a command line: "Net user <account_name> /passwordreq:yes".'
  tag checktext: 'Verify all accounts require passwords.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
PswdRequired
AcctDisabled
Groups

If any accounts have "No" in the "PswdRequired" column, this is a finding.

Some built-in or application-generated accounts (e.g., Guest, IWAM_, IUSR, etc.) may not have this flag set, even though there are passwords present.  It can be set by entering the following on a command line: "Net user <account_name> /passwordreq:yes".'

# START_DESCRIBE V-7002
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-7002

end

