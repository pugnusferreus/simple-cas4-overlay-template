#!/bin/bash

export JAVA_HOME=$(/usr/libexec/java_home -v 1.7)
mvn clean package
rm -rf /Users/pugnusferreus/apache-tomcat-7.0.53/webapps/cas
rm /Users/pugnusferreus/apache-tomcat-7.0.53/webapps/cas.war
cp target/cas.war /Users/pugnusferreus/apache-tomcat-7.0.53/webapps/
