# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-36724 - Permissions for the System event log must prevent access by nonprivileged accounts.'
control 'V-36724' do
  impact 0.5
  title 'Permissions for the System event log must prevent access by nonprivileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The System event log may be  susceptible to tampering if proper permissions are not applied.'
  tag 'stig', 'V-36724'
  tag severity: 'medium'
  tag checkid: 'C-46835r1_chk'
  tag fixid: 'F-44701r1_fix'
  tag version: 'WN12-AU-000206'
  tag ruleid: 'SV-51572r1_rule'
  tag fixtext: 'Ensure the permissions on the System event log (System.evtx) are configured to prevent standard user accounts or groups from having greater than Read access.  The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\Eventlog".'
  tag checktext: 'Verify the permissions on the System event log (System.evtx).  Standard user accounts or groups must not have greater than Read access.  The default permissions listed below satisfy this requirement:

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory.  They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.'

# START_DESCRIBE V-36724
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-36724

end

