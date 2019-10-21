#!/bin/bash

MESSAGE=$(git log -1 HEAD --pretty=format:%s)

echo "Checking whether we need to commit changes"

if [[ "$MESSAGE" == *\[bot\]* ]]; then
        echo "previous commit was by bot. aborting"
else
    if [[ "$MESSAGE" == *\[skip\ ci\]* ]]; then
            echo "skipping commit as requested"
    else
            ./commit.sh
    fi
fi