#!/bin/bash

sudo mkdir -p /sys/fs/cgroup/memory_test
sudo mkdir /sys/fs/cgroup/memory_test/test_oom

echo 1G | sudo tee /sys/fs/cgroup/memory_test/test_oom/memory.max

echo 1 | sudo tee /sys/fs/cgroup/memory_test/test_oom/memory.oom.group

echo $$ | sudo tee /sys/fs/cgroup/memory_test/test_oom/cgroup.procs

gcc -o oom_test oom_test.c

sudo sh -c 'echo $$ > /sys/fs/cgroup/memory_test/test_oom/cgroup.procs && ./oom_test'
