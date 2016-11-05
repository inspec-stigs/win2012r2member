# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-06-08
# description: The Windows Server 2012 / 2012 R2 Member Server Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems. Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts
title 'V-3289 - Servers must have a host-based Intrusion Detection System.'
control 'V-3289' do
  impact 0.5
  title 'Servers must have a host-based Intrusion Detection System.'
  desc 'A properly configured host-based Intrusion Detection System provides another level of defense against unauthorized access to critical servers.  With proper configuration and logging enabled, such a system can stop and/or alert for many attempts to gain unauthorized access to resources.'
  tag 'stig', 'V-3289'
  tag severity: 'medium'
  tag checkid: 'C-46922r3_chk'
  tag fixid: 'F-45130r1_fix'
  tag version: 'WN12-GE-000022'
  tag ruleid: 'SV-52105r3_rule'
  tag fixtext: 'Install a host-based Intrusion Detection System on each server.'
  tag checktext: 'Determine whether there is a host-based Intrusion Detection System on each server. 

If the HIPS component of HBSS is installed and active on the host and the Alerts of blocked activity are being logged and monitored, this will meet the requirement of this finding. 

A HID device is not required on a system that has the role as the Network Intrusion Device (NID). However, this exception needs to be documented with the site ISSO.

If a host-based Intrusion Detection System is not installed on the system, this is a finding.'

# START_DESCRIBE V-3289
      describe file('') do
      it "is a pending example"
      # it { should match // }
    end

# STOP_DESCRIBE V-3289

end

