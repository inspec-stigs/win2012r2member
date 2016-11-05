# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1135 - Nonadministrative user accounts or groups must only have print permissions on printer shares.'
control 'V-1135' do
  impact 0.1
  title 'Nonadministrative user accounts or groups must only have print permissions on printer shares.'
  desc 'Windows shares are a means by which files, folders, printers, and other resources can be published for network users to access.  Improper configuration can permit access to devices and data beyond a users need.'
  tag 'stig', 'V-1135'
  tag severity: 'low'
  tag checkid: 'C-46959r1_chk'
  tag fixid: 'F-45232r1_fix'
  tag version: 'WN12-GE-000012'
  tag ruleid: 'SV-52213r1_rule'
  tag fixtext: 'Configure the permissions on shared printers to restrict standard users to  only have Print permissions.  This is typically given through the Everyone group by default.'
  tag checktext: 'Open "Devices and Printers" in Control Panel or through Search.
If there are no printers configured, this is NA.

For each configured printer:
Right click on the printer. 
Select "Printer Properties". 
Select the "Sharing" tab. 
View whether "Share this printer" is checked. 

For any printers with "Share this printer" selected: 
Select the Security tab. 

If any standard user accounts or groups have permissions other than "Print", this is a finding.
Standard users will typically be given "Print" permission through the Everyone group.
"All APPLICATION PACKAGES" and "CREATOR OWNER" are not considered standard user accounts for this requirement.'

# START_DESCRIBE V-1135
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1135

end

