#!/usr/bin/env bash

#####################################################################################
# Script for building the app without depending on a local Java / Maven environment.
# Requires docker to be installed and available to the current user!
#
# The script will do a "mvn clean install". Any options passed to the script will be
# appended. For example, run as follows:
#
#      ./build.sh -DskipTests=true -Pdocker
#
# By default a Maven cache is persisted through a volume. To reset the cache, export
# the CLEAN_CACHE property. For example:
#
#      CLEAN_CACHE=true ./build.sh -Pdevelop
#
#####################################################################################

#configuration
APP_NAME="epicify"
MAVEN_IMAGE="maven:3.6.3-jdk-11-slim"
CLEAN_CACHE=${CLEAN_CACHE:-false}

SCRIPT_DIR="$( cd "$(dirname "$0")" ; pwd -P )"
MAVEN_CONFIG_IMAGE="${APP_NAME}-maven-build-cache"
MAVEN_CONFIG_DIR="/root/.m2"
BUILD_CONTAINER_NAME="${APP_NAME}-maven-build"

MAVEN_OPTS="$@"
MAVEN_CMD="mvn clean ${MAVEN_OPTS}"

if ! [ "${JAVA_SRC_DIR}" ]; then
  JAVA_SRC_DIR="$( cd ${SCRIPT_DIR} ; pwd -P )"
fi

if ! [ -d "${JAVA_SRC_DIR}" ]; then
	echo "Source directory ${JAVA_SRC_DIR} not found"
	exit 1
fi

#### MAIN FUNCTIONS

main() {
	check_docker
	pull_image
	prepare_cache_volume
	copy_m2-settings

	echo "Source dir: ${JAVA_SRC_DIR}" 
	echo "Maven command: ${MAVEN_CMD}"
	echo "Build image: ${MAVEN_IMAGE}"

	docker_run
}

#### HELPER FUNCTIONS

check_docker() {
	if ! which docker > /dev/null; then
		echo "Docker command not found"
		exit 1
	fi
}

pull_image() {
	if ! docker pull "${MAVEN_IMAGE}"; then
		echo "Failed to pull Maven image for build"
		exit 1
	fi
}

prepare_cache_volume() {
	if docker volume ls -f "name=${MAVEN_CONFIG_IMAGE}"|grep "${MAVEN_CONFIG_IMAGE}"; then
		if ${CLEAN_CACHE}; then
			echo "Removing Maven cache volume ${MAVEN_CONFIG_IMAGE}"
			docker volume rm "${MAVEN_CONFIG_IMAGE}"
		else
			echo "Using existing Maven cache volume ${MAVEN_CONFIG_IMAGE}"
		fi
	else
		echo "Creating Maven cache volume ${MAVEN_CONFIG_IMAGE}"
		docker volume create "${MAVEN_CONFIG_IMAGE}"
	fi
}

copy_m2-settings() {
	if [ -d m2-settings ]; then
		docker run -d --rm --name ${APP_NAME}-settings -v ${MAVEN_CONFIG_IMAGE}:/root alpine tail -f /dev/null
		#docker exec ${APP_NAME}-settings mkdir -p ${MAVEN_CONFIG_DIR}
		if [ -f m2-settings/settings.xml ]; then
			docker cp m2-settings/settings.xml ${APP_NAME}-settings:/root/settings.xml
		fi
		if [ -f m2-settings/settings-security.xml ]; then
			docker cp m2-settings/settings-security.xml ${APP_NAME}-settings:/root/settings-security.xml
		fi
		#docker exec ${APP_NAME}-settings ls -all /root
		docker stop ${APP_NAME}-settings
		#docker run -d --rm --name ${APP_NAME}-settings -v "${MAVEN_CONFIG_IMAGE}":"${MAVEN_CONFIG_DIR}" alpine tail -f /dev/null
		#docker exec ${APP_NAME}-settings ls -all ${MAVEN_CONFIG_DIR}
		#docker stop ${APP_NAME}-settings
	fi
}

docker_run() {
	docker run \
		--rm \
		--name "${BUILD_CONTAINER_NAME}" \
		-v "${MAVEN_CONFIG_IMAGE}":"${MAVEN_CONFIG_DIR}" \
		-e MAVEN_CONFIG="${MAVEN_CONFIG_DIR}" \
		-v "${JAVA_SRC_DIR}":/var/src  \
		-w /var/src \
		"${MAVEN_IMAGE}" ${MAVEN_CMD}
}

# Execute main
main
