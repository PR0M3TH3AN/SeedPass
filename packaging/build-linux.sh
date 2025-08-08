#!/bin/bash
set -e
briefcase create linux --no-input
briefcase build linux --no-input
briefcase package linux --no-input
