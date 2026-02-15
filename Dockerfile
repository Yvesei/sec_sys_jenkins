FROM jenkins/jenkins:latest

USER root

# Set environment variables to skip setup wizard
ENV JENKINS_SKIP_SETUP_WIZARD=true
ENV JAVA_OPTS="-Dcom.cloudbees.jenkins.MasterProvisioning=disable -Djenkins.install.SkipSetupWizard=true"

# Ensure Jenkins home and log directories exist and are writable
RUN mkdir -p /var/jenkins_home /var/log/jenkins \
    && chown -R jenkins:jenkins /var/jenkins_home /var/log/jenkins

# Copy plugins file (if you have one)
# COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
# RUN jenkins-plugin-cli -f /usr/share/jenkins/ref/plugins.txt

# Create Groovy init scripts directory
RUN mkdir -p /usr/share/jenkins/ref/init.groovy.d

# Copy Groovy init scripts for automatic configuration (execute in order)
# These scripts will:
# - Create admin:admin user
# - Skip setup wizard
# - Configure comprehensive logging
COPY basic-security.groovy /usr/share/jenkins/ref/init.groovy.d/000-basic-security.groovy
COPY configure-jenkins.groovy /usr/share/jenkins/ref/init.groovy.d/001-configure-jenkins.groovy
COPY init.groovy /usr/share/jenkins/ref/init.groovy.d/002-init.groovy
COPY jenkins-logging-init.groovy /usr/share/jenkins/ref/init.groovy.d/003-jenkins-logging-init.groovy

# Set proper permissions on init scripts
RUN chmod -R 755 /usr/share/jenkins/ref/init.groovy.d && \
    chown -R jenkins:jenkins /usr/share/jenkins/ref/init.groovy.d

# Copy enhanced startup script with comprehensive logging
COPY jenkins-with-logging.sh /usr/local/bin/jenkins-with-logging.sh
RUN chmod +x /usr/local/bin/jenkins-with-logging.sh

USER jenkins

ENTRYPOINT ["/usr/local/bin/jenkins-with-logging.sh"]