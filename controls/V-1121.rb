# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-1121 - FTP servers must be configured to prevent access to the system drive.'
control 'V-1121' do
  impact 1.0
  title 'FTP servers must be configured to prevent access to the system drive.'
  desc 'The FTP service allows remote users to access shared files and directories which could provide access to system resources and compromise the system, especially if the user can gain access to the root directory of the boot drive.'
  tag 'stig', 'V-1121'
  tag severity: 'high'
  tag checkid: 'C-46958r1_chk'
  tag fixid: 'F-45231r1_fix'
  tag version: 'WN12-GE-000027'
  tag ruleid: 'SV-52212r1_rule'
  tag fixtext: 'Configure the system to prevent an FTP service from allowing access to the system drive.'
  tag checktext: 'If FTP is not installed on the system, this is NA.  

Open a "Command Prompt".
Log on using an authenticated FTP account, and attempt to access the root of the boot drive with the following commands:

X:\>ftp 127.0.0.1
(Connected to "servername".
220 "servername" Microsoft FTP Service (Version 2.0).)

User: "ftpuser"
(331 Password required for ftpuser.)

Password: "password"
(230 User ftpuser logged in.)

ftp> dir

If the FTP session indicates access to areas of the operating system such as Program Files and Windows directories, this is a finding.'

# START_DESCRIBE V-1121
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-1121

end

