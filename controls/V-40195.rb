# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40195 - System BIOS or system controllers must not allow user-level access.'
control 'V-40195' do
  impact 0.5
  title 'System BIOS or system controllers must not allow user-level access.'
  desc 'A systems BIOS or system controller handles the initial startup of a system, and its configuration must be protected from unauthorized modification.  When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators.  Failure to protect BIOS or system controller settings could result in Denial of Service or compromise of the system resulting from unauthorized configuration changes.'
  tag 'stig', 'V-40195'
  tag severity: 'medium'
  tag checkid: 'C-46950r2_chk'
  tag fixid: 'F-45179r2_fix'
  tag version: 'WN12-00-000002-02'
  tag ruleid: 'SV-52153r2_rule'
  tag fixtext: 'Access the systems BIOS or system controller.   Disable user-level access.

Restrictions may also be applied through hypervisor configuration settings for virtual machines.'
  tag checktext: 'If the BIOS or system controller does not support user-level access in addition to supervisor/administrator access, this is NA.

If the BIOS or system controller supports user-level access in addition to supervisor/administrator access, determine whether this access is enabled.  If user-level access is enabled, this is a finding.

If access is restricted by way of hypervisor configuration settings on virtual systems, this would not be a finding.'

# START_DESCRIBE V-40195
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40195

end

