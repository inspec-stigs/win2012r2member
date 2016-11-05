# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-57637 - The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
control 'V-57637' do
  impact 0.5
  title 'The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities.  The organization must identify authorized software programs and only permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.'
  tag 'stig', 'V-57637'
  tag severity: 'medium'
  tag checkid: 'C-69283r2_chk'
  tag fixid: 'F-66567r4_fix'
  tag version: 'WN12-00-000018'
  tag ruleid: 'SV-72047r4_rule'
  tag fixtext: 'This is applicable to unclassified systems, for other systems this is NA.

Configure an application whitelisting program to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

Configuration of whitelisting applications will vary by the program.  AppLocker is a whitelisting application built into Windows Server 2012.

If AppLocker is used, it is configured through group policy in Computer Configuration >> Windows Settings >> Security Settings >> Application Control Policies >> AppLocker.

Implementation guidance for AppLocker is available in the NSA paper "Application Whitelisting using Microsoft AppLocker" under the Microsoft Windows section of the following link:

https://www.nsa.gov/ia/mitigation_guidance/security_configuration_guides/operating_systems.shtml'
  tag checktext: 'This is applicable to unclassified systems, for other systems this is NA.

Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of authorized software programs.

If an application whitelisting program is not in use on the system, this is a finding.

Configuration of whitelisting applications will vary by the program.

AppLocker is a whitelisting application built into Windows Server 2012.  A deny-by-default implementation is initiated by enabling any AppLocker rules within a category, only allowing what is specified by defined rules.

If AppLocker is used, perform the following to view the configuration of AppLocker:
Open PowerShell.

If the AppLocker PowerShell module has not been previously imported, execute the following first:
Import-Module AppLocker

Execute the following command, substituting [c:\temp\file.xml] with a location and file name appropriate for the system:
Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml

This will produce an xml file with the effective settings that can be viewed in a browser or opened in a program such as Excel for review.

Implementation guidance for AppLocker is available in the NSA paper "Application Whitelisting using Microsoft AppLocker" under the Microsoft Windows section of the following link:

https://www.nsa.gov/ia/mitigation_guidance/security_configuration_guides/operating_systems.shtml'

# START_DESCRIBE V-57637
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-57637

end

