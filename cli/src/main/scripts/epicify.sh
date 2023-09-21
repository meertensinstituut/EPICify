#!/bin/bash

JAVA="java"
READLINK="readlink"

function ensureSlash(){
  length=${1}-1

  # If the parameter passed to the function does not end with a slash, append
  # one and return the result
  if [ "{$1:length}" != "/" ]; then
    echo ${1}/
  fi
}

export LANG=en_US.UTF-8

# Do not assume the script is invoked from the directory it is located in; get
# the directory the script is located in
thisDir="$(dirname "$(${READLINK} -f "$0")")"
if [ -f ${thisDir}/epicify-${version}.jar ]; then
  JAR="-jar ${thisDir}/epicify-${version}.jar"
elif [ -f ${EPICIFY_HOME}/epicify-${version}.jar ]; then
  JAR="-jar ${EPICIFY_HOME}/epicify-${version}.jar"
elif [ -f ${HOME}/.epicify/epicify-${version}.jar ]; then
  JAR="-jar ${HOME}/.epicify/epicify-${version}.jar"
else
  echo "WRN: didn't find epicify-${version}.jar, trying the CLASSPATH!"
fi

nice ${JAVA} ${JAR} $*