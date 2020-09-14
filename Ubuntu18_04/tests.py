import base64, pytest


# CAT II | UBTU-18-010002 | Configuring the Ubuntu operating system to produce audit records at system startup
# grep "^\s*linux" /boot/grub/grub.cfg
def test_ubtu_18_010002(host):
    content_file = host.file('/boot/grub/grub.cfg').content_string

    for line in content_file:
        line += host.file(content_file).re.search("^\s*linux", "linux")

    assert line.contains("audit=1")


# CAT II | UBTU-18-010003 | Ubuntu operating systems handling data requiring data at rest protections must employ
# cryptographic mechanisms
def test_ubtu_18_010003(host):
    output = host.check_output('fdisk -l')
    assert host.file("/etc/crypttab").contains(host.get_filesystem_partition('/'))


# CAT II | UBTU-18-010016 | Advanced package tool (APT) must be configured
def test_ubtu_18_010016(host):
    assert not host.file("/etc/apt/apt.conf.d/*").contains('AllowUnauthenticated "true"')


# CAT II | UBTU-18-010017 | configure the (APT) so that it removes unused dependencies
def test_ubtu_18_010017(host):
    test_string = '# '
    assert host.file("/etc/apt/apt.conf.d/").contains("Unattended-Upgrade::Remove-Unused-Dependencies") and host.file(
        "/etc/apt/apt.conf.d/50unattended-upgrades").contains(
        'Unattended-Upgrade::Remove-Unused-Kernel-Packages "true"') \
           and not host.file("/etc/apt/apt.conf.d/").contains(test_string)


# CAT II | UBTU-18-010021 | Verify the Ubuntu operating system deploys ENSLTP
# Validate that the [isectp] package is installed
def test_ubtu_18_010021_isectp_is_installed(host):
    assert host.package("isectp").is_installed


# Validate that the isectp daemon is running
def test_ubtu_18_010021_isectp_daemon_is_running(host):
    assert host.service("isectp").is_running


# CAT II | UBTU-18-010022 | Verify the log service is configured to collect system failure events
# Check that the log service is properly installed
def test_ubtu_18_010022(host):
    assert host.check_output("dpkg -l | grep rsyslog") == 'ii rsyslog 8.32.0-1ubuntu4 amd64 reliable system and ' \
                                                          'kernel logging daemon '


# Check that the log service is enabled
def test_ubtu_18_01022_check_log_service_enabled(host):
    assert host.service('rsyslog').is_enabled


# Check that rsyslog is running correctly on the system
def test_ubtu_18_01022_checkLogDaemon(host):
    assert host.service('rsyslog').is_running


# CAT II | UBTU-18-010023 | Verify that the Uncomplicated Firewall is installed
def test_ubtu_18_010023(host):
    assert host.package('ufw').is_installed


# CAT II | UBTU-18-010033 | Check that Ubuntu operating system locks an account after three unsuccessful login
# attempts UBTU-18-010033-CATII
def test_ubtu_18_010033(host):
    test_string = 'onerr = fail'
    test_string_comment = '#'
    test_string_deny = 'deny=3'
    other_values = 'deny=2'
    other_values_2 = 'deny=1'
    output = host.check_output("grep pam_tally2 /etc/pam.d/common-auth")

    # a line is returned, the line is NOT commented out AND the line is NOT missing "onerr=fail" AND the line has
    # 'deny' value of 3 or less
    assert len(output) > 0 and (not (test_string_comment in output)) and (test_string in output) and \
           (test_string_deny in output or other_values in output or other_values_2 in output)


# CAT II | UBTU-18-010035 | The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent
# Check that the operating system displays the exact approved Standard Mandatory DoD Notice and Consent Banner text
def test_ubtu_18_010035(host):
    assert host.check_output(
        "grep banner-message-enable /etc/gdm3/greeter.dconf-defaults") == 'banner-message-enable=true'


# If the line is commented out or set to "false", this is a finding.
def test_ubtu_18_010035(host):
    assert host.check_output("grep banner-message-text /etc/gdm3/greeter.dconf-defaults") == \
           'banner-message-text="You are accessing a U.S. Government \(USG\) Information System \(IS\) that is provided ' \
           'for USG-authorized use only.\s+By using this IS \(which includes any device attached to this IS\), ' \
           'you consent to the following conditions:\s+-The USG routinely intercepts and monitors communications on this ' \
           'IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations ' \
           'and defense, personnel misconduct \(PM\), law enforcement \(LE\), and counterintelligence \(CI\) ' \
           'investigations.\s+-At any time, the USG may inspect and seize data stored on this IS.\s+-Communications ' \
           'using, or data stored on, this IS are not private, are subject to routine monitoring, interception, ' \
           'and search, and may be disclosed or used for any USG-authorized purpose.\s+-This IS includes security ' \
           'measures \(e.g., authentication and access controls\) to protect USG interests--not for your personal ' \
           'benefit or privacy.\s+-Notwithstanding the above, using this IS does not constitute consent to PM, ' \
           'LE or CI investigative searching or monitoring of the content of privileged communications, or work product, ' \
           'related to personal representation or services by attorneys, psychotherapists, or clergy, and their ' \
           'assistants. Such communications and work product are private and confidential. See User Agreement for ' \
           'details." '


# name: CAT II | UBTU-18-010036 | Verify the Ubuntu operating system prevents direct logins to the root account.
# 'L' character validates the account lock for this scenario
def test_ubtu_18_010036(host):
    check_string = 'L'
    output = host.check_output('passwd -S root')
    assert check_string in output


# CAT II | UBTU-18-010038 | Check the specified banner file to check that it matches the Standard Mandatory DoD
# Check for correct output and that line is not commented out
def test_ubtu_18_010038(host):
    assert host.check_output(" grep -i banner /etc/ssh/sshd_config") == 'Banner /etc/issue' and not host.file(
        "/etc/ssh/sshd_config").contains("# ")


# CAT II | UBTU-18-010038 | Check the specified banner file to check that it matches the Standard Mandatory DoD
# Check banner for exact match
def test_ubtu_18_010038(host):
    assert host.check_output("cat /etc/issue") == \
           'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use ' \
           'only. \ By using this IS (which includes any device attached to this IS), you consent to the following ' \
           'conditions: \ -The USG routinely intercepts and monitors communications on this IS for purposes ' \
           'including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, ' \
           'personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. \ -At any ' \
           'time, the USG may inspect and seize data stored on this IS. \ -Communications using, or data stored on, ' \
           'this IS are not private, are subject to routine monitoring, interception, and search, and may be ' \
           'disclosed or used for any USG-authorized purpose. \ -This IS includes security measures (e.g., ' \
           'authentication and access controls) to protect USG interests--not for your personal benefit or privacy. \ ' \
           '-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative ' \
           'searching or monitoring of the content of privileged communications, or work product, related to personal ' \
           'representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such ' \
           'communications and work product are private and confidential. See User Agreement for details. '


# CAT II | UBTU-18-010104 | Verify that the shadow password suite configuration is set to encrypt password with a
# FIPS 140-2 approved cryptographic hashing algorithm
def test_ubtu_18_010104(host):
    assert host.check_output("cat /etc/login.defs | grep -i crypt") == 'ENCRYPT_METHOD SHA512'


# CAT II | UBTU-18-010109 | The Ubuntu operating system must enforce a minimum 15-character password length.
def test_ubtu_18_010109(host):
    assert host.check_output("grep -i minlen /etc/security/pwquality.conf") == 'minlen=15'


# CAT II | UBTU-18-010110 | The Ubuntu operating system must employ a FIPS 140-2 approved cryptographic hashing
# algorithms for all created and stored passwords.
def test_ubtu_18_010110(host):
    assert host.check_output("grep password /etc/pam.d/common-password | grep pam_unix") == 'password [success=1 ' \
                                                                                            'default=ignore] ' \
                                                                                            'pam_unix.so obscure sha512 '


# CAT II | UBTU-18-010110 | The Ubuntu operating system must employ a FIPS 140-2 approved cryptographic hashing
# If "sha512" is not an option of the output, or is commented out, this is a finding.
# Check that ENCRYPT_METHOD is set to sha512 in /etc/login.defs:
def test_ubtu_18_010110_Encrypt_Method(host):
    assert host.check_output("grep -i ENCRYPT_METHOD /etc/login.defs") == 'ENCRYPT_METHOD SHA512'


# CAT II | UBTU-18-010112 | The Ubuntu operating system must allow the use of a temporary password for system logons
# with an immediate change to a permanent password.
def test_ubtu_18_010112(host):
    assert host.check_output("chage -d 0 [UserName]")


# CAT II | UBTU-18-010113 | Verify that the Ubuntu operating system uses the cracklib library to prevent the use of
# dictionary words
def test_ubtu_18_010113(host):
    assert host.check_output("grep dictcheck /etc/security/pwquality.conf") == 'dictcheck=1'


# CAT II | UBTU-18-010114 | The Ubuntu operating system must require users to re-authenticate for privilege
# escalation and changing roles.
def test_ubtu_18_010114(host):
    test_string = 'NOPASSWD'
    test_string2 = '!authenticate'
    assert test_string not in host.check_output(
        "sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*") \
           and test_string2 not in host.check_output(
        "sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*")


# CAT II | UBTU-18-010116 | The Ubuntu Operating system must be configured so that when passwords are changed or new
# passwords are established, pwquality must be used.
def test_ubtu_18_010116_password_strength(host):
    assert host.check_output("dpkg -l libpam-pwquality") == 'ii libpam-pwquality:amd64 1.4.0-2 amd64 PAM module to ' \
                                                            'check password strength '


# CAT II | UBTU-18-010116 | If the value of "enforcing" is not 1 or the line is commented out, this is a finding.
def test_ubtu_18_010116_enforce_pass_complexity(host):
    test_string = "# "
    assert host.check_output("grep -i enforcing /etc/security/pwquality.conf") == 'enforcing = 1' and \
           test_string not in host.check_output("grep -i enforcing /etc/security/pwquality.conf")


# CAT II | UBTU-18-010116 | Check for the use of "pwquality"
# If no output is returned or the line is commented out, this is a finding.
# If the value of "retry" is set to "0" or greater than "3", this is a finding.
def test_ubtu_18_010116_check_for_pwqual(host):
    test_string = "# "
    assert host.check_output("sudo cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality") == \
           'password requisite pam_pwquality.so retry=3' and test_string not in \
           host.check_output("sudo cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality") and not \
               host.file("/etc/pam.d/common-password").contains("retry=0") and not \
               host.file("/etc/pam.d/common-password").contains("retry=4")

