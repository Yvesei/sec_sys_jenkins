#!/bin/bash
set -e

echo "================================================================"
echo "Starting Jenkins with Comprehensive Logging"
echo "================================================================"

# Create log directories
mkdir -p /var/log/jenkins
chmod 777 /var/log/jenkins

echo "[*] Log directories created"

# Create logging configuration
cat > /var/log/jenkins/logging.properties <<EOF
# Root logger
.level=INFO
handlers=java.util.logging.ConsoleHandler,java.util.logging.FileHandler

# Console Handler
java.util.logging.ConsoleHandler.level=FINE
java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter

# File Handler
java.util.logging.FileHandler.pattern=/var/log/jenkins/jenkins.log
java.util.logging.FileHandler.limit=50000000
java.util.logging.FileHandler.count=5
java.util.logging.FileHandler.formatter=java.util.logging.SimpleFormatter
java.util.logging.FileHandler.level=FINE

# Jetty HTTP Request Logging
org.eclipse.jetty.level=FINE
org.eclipse.jetty.server.level=FINE
org.eclipse.jetty.server.Request.level=FINE
org.eclipse.jetty.server.Response.level=FINE

# Jenkins specific logging
hudson.level=FINE
jenkins.level=FINE

# Detailed formatter
java.util.logging.SimpleFormatter.format=[%1\$tF %1\$tT] [%4\$-7s] %2\$s %5\$s%6\$s%n
EOF

echo "[*] Logging configuration created"

cd /usr/share/jenkins

echo "[*] Starting Jenkins with comprehensive logging options..."
echo "    - Access logs: /var/log/jenkins/access.log"
echo "    - Detailed logs: /var/log/jenkins/detailed-access.log"
echo "    - Jenkins logs: /var/log/jenkins/jenkins.log"
echo "================================================================"

exec java -Dcom.sun.akuma.Daemon=false \
     -Djava.awt.headless=true \
     -Djava.util.logging.config.file=/var/log/jenkins/logging.properties \
     -Dorg.eclipse.jetty.LEVEL=DEBUG \
     -Dorg.eclipse.jetty.server.LEVEL=DEBUG \
     -Dorg.eclipse.jetty.server.Request.LEVEL=DEBUG \
     -Dhudson.model.AbstractItem.LOGGER.level=FINE \
     -jar jenkins.war \
     --httpPort=8080 \
     --accessLoggerClassName=winstone.accesslog.SimpleAccessLogger \
     --simpleAccessLogger.format=combined \
     --simpleAccessLogger.file=/var/log/jenkins/access.log \
     --debug=9 \
     --logfile=/var/log/jenkins/jenkins.log