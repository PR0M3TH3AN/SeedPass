#!/bin/bash
set -e
briefcase create macos --no-input
briefcase build macos --no-input
briefcase package macos --no-input
