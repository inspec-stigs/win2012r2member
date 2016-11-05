# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-26602 - The Microsoft FTP service must not be installed.'
control 'V-26602' do
  impact 0.5
  title 'The Microsoft FTP service must not be installed.'
  desc 'Unnecessary services increase the attack surface of a system. Some of these services may not support required levels of authentication or encryption.'
  tag 'stig', 'V-26602'
  tag severity: 'medium'
  tag checkid: 'C-69287r1_chk'
  tag fixid: 'F-74887r1_fix'
  tag version: 'WN12-SV-000101'
  tag ruleid: 'SV-52237r3_rule'
  tag fixtext: 'Remove or disable the "Microsoft FTP Service" (Service name: FTPSVC).   

To remove the "FTP Server" role from a system:
Start "Server Manager"
Select the server with the "FTP Server" role.
Scroll down to "ROLES AND FEATURES" in the left pane.
Select "Remove Roles and Features" from the drop down "TASKS" list.
Select the appropriate server on the "Server Selection" page, click "Next".
De-select "FTP Server" under "Web Server (IIS).
Click "Next" and "Remove" as prompted.'
  tag checktext: 'If the server has the role of an FTP server, this is NA.
Run "Services.msc".

If the "Microsoft FTP Service" (Service name: FTPSVC) is installed and not disabled, this is a finding.'

# START_DESCRIBE V-26602
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-26602

end

