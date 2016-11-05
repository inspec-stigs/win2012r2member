# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-15823 - Software certificate installation files must be removed from a system.'
control 'V-15823' do
  impact 0.5
  title 'Software certificate installation files must be removed from a system.'
  desc 'Use of software certificates and their accompanying installation files for end users to access resources is less secure than the use of hardware-based certificates.'
  tag 'stig', 'V-15823'
  tag severity: 'medium'
  tag checkid: 'C-47447r2_chk'
  tag fixid: 'F-46067r1_fix'
  tag version: 'WN12-GE-000020'
  tag ruleid: 'SV-53141r2_rule'
  tag fixtext: 'Remove any certificate installation files (*.p12 and *.pfx) found on a system.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).'
  tag checktext: 'Search all drives for *.p12 and *.pfx files.

If any files with these extensions exist, this is a finding.

This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager).  Some applications create files with extensions of .p12 that are NOT certificate installation files.  Removal of noncertificate installation files from systems is not required.  These must be documented with the ISSO.'

# START_DESCRIBE V-15823
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-15823

end

