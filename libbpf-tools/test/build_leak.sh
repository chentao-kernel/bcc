#!/bin/bash

gcc -o leak leak.c -fomit-frame-pointer -O2
