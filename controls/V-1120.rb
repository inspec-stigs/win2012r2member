# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1120 - FTP servers must be configured to prevent anonymous logons.'
control 'V-1120' do
  impact 0.5
  title 'FTP servers must be configured to prevent anonymous logons.'
  desc 'The FTP (File Transfer Protocol) service allows remote users to access shared files and directories.  Allowing anonymous FTP connections makes user auditing difficult.  Using accounts that have administrator privileges to log on to FTP risks that the userid and password will be captured on the network and give administrator access to an unauthorized user.'
  tag 'stig', 'V-1120'
  tag severity: 'medium'
  tag checkid: 'C-46923r1_chk'
  tag fixid: 'F-45131r1_fix'
  tag version: 'WN12-GE-000026'
  tag ruleid: 'SV-52106r1_rule'
  tag fixtext: 'Configure the system to prevent an installed FTP service from allowing anonymous logons.'
  tag checktext: 'If FTP is not installed on the system, this is NA.  

Open a "Command Prompt".
Attempt to log on as the user "anonymous" with the following commands:

C:\>ftp localhost
(Connected to "servername".
220 Microsoft FTP Service)

User: anonymous
(331 Anonymous access allowed, send identity (e-mail name) as password.)

Password: password
(230 User logged in.)
ftp>

If the command response indicates that an anonymous FTP login was permitted, this is a finding.'

# START_DESCRIBE V-1120
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1120

end

