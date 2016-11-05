# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-40178 - Permissions for system drive root directory (usually C:\) must conform to minimum requirements.'
control 'V-40178' do
  impact 0.5
  title 'Permissions for system drive root directory (usually C:\) must conform to minimum requirements.'
  desc 'Changing the systems file and directory permissions allows the possibility of unauthorized and anonymous modification to the operating system and installed applications.  The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).'
  tag 'stig', 'V-40178'
  tag severity: 'medium'
  tag checkid: 'C-46947r2_chk'
  tag fixid: 'F-45162r1_fix'
  tag version: 'WN12-GE-000006'
  tag ruleid: 'SV-52136r3_rule'
  tag fixtext: 'Maintain the default permissions for the system drives root directory and configure the Security Option: "Network access: Let everyone permissions apply to anonymous users" to "Disabled" (V-3377).

Default Permissions
C:\
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

SYSTEM - Full control - This folder, subfolders and files
Administrators - Full control - This folder, subfolders and files
Users - Read & execute - This folder, subfolders and files
Users - Create folders / append data - This folder and subfolders
Users - Create files / write data - Subfolders only
CREATOR OWNER - Full Control - Subfolders and files only'
  tag checktext: 'The default permissions are adequate when the Security Option "Network access: Let everyone permissions apply to anonymous users" is set to "Disabled" (V-3377).  If the default ACLs are maintained and the referenced option is set to "Disabled", this is not a finding.

Verify the default permissions for the system drives root directory (usually C:\).  Nonprivileged groups such as Users or Authenticated Users must not have greater than Read & execute permissions except where noted as defaults.  (Individual accounts must not be used to assign permissions.)

Viewing in File Explorer:
View the Properties of system drive root directory.
Select the "Security" tab, and the "Advanced" button.

C:\
Type - "Allow" for all
Inherited from - "None" for all

Principal - Access - Applies to

SYSTEM - Full control - This folder, subfolders and files
Administrators - Full control - This folder, subfolders and files
Users - Read & execute - This folder, subfolders and files
Users - Create folders / append data - This folder and subfolders
Users - Create files / write data - Subfolders only
CREATOR OWNER - Full Control - Subfolders and files only

Alternately, use Icacls:

Open a Command prompt (admin).
Enter icacls followed by the directory:

icacls c:\

The following results should be displayed:

c:\
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Administrators:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
BUILTIN\Users:(CI)(AD)
BUILTIN\Users:(CI)(IO)(WD)
CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files'

# START_DESCRIBE V-40178
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-40178

end

