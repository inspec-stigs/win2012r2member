# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57721 - Event Viewer must be protected from unauthorized modification and deletion.'
control 'V-57721' do
  impact 0.5
  title 'Event Viewer must be protected from unauthorized modification and deletion.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.  Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the modification or deletion of audit tools.'
  tag 'stig', 'V-57721'
  tag severity: 'medium'
  tag checkid: 'C-58513r2_chk'
  tag fixid: 'F-62927r2_fix'
  tag version: 'WN12-AU-000213'
  tag ruleid: 'SV-72135r2_rule'
  tag fixtext: 'Ensure only TrustedInstaller has permissions to change or modify Event Viewer ("%SystemRoot%\SYSTEM32\Eventvwr.exe).

The default permissions below satisfy this requirement.
TrustedInstaller - Full Control
Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES - Read & Execute'
  tag checktext: 'Verify the permissions on Event Viewer only allow TrustedInstaller permissions to change or modify.  If any groups or accounts other than TrustedInstaller have Full control or Modify, this is a finding.

Navigate to "%SystemRoot%\SYSTEM32".
View the permissions on "Eventvwr.exe".

The default permissions below satisfy this requirement.
TrustedInstaller - Full Control
Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES - Read & Execute'

# START_DESCRIBE V-57721
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57721

end

