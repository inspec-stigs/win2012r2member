# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-56511 - The Windows Error Reporting Service must be running and configured to start automatically.'
control 'V-56511' do
  impact 0.5
  title 'The Windows Error Reporting Service must be running and configured to start automatically.'
  desc 'Windows Error Reporting information can be used to help diagnose day-to-day software issues, as well as help discover malicious code and possibly zero-day attacks on systems.'
  tag 'stig', 'V-56511'
  tag severity: 'medium'
  tag checkid: 'C-58069r2_chk'
  tag fixid: 'F-62433r2_fix'
  tag version: 'WN12-ER-000001'
  tag ruleid: 'SV-71667r1_rule'
  tag fixtext: 'Configure the Start Type of the Windows Error Reporting Service to "Automatic" and ensure the service has a status of "Running".'
  tag checktext: 'Verify the Start Type and Status of the Windows Error Reporting Service.

Run "Services.msc".
If the Windows Error Reporting Service does not have a Status of "Running" and a Start Type of "Automatic", this is a finding.'

# START_DESCRIBE V-56511
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-56511

end

