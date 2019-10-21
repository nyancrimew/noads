#!/bin/sh
# Based on https://github.com/elstudio/actions-js-build/blob/master/commit/entrypoint.sh
now=$(date +"%T %D")

git_setup ( ) {
  cat <<- EOF > $HOME/.netrc
		machine github.com
		login $GITHUB_ACTOR
		password $GITHUB_TOKEN
		machine api.github.com
		login $GITHUB_ACTOR
		password $GITHUB_TOKEN
EOF
  chmod 600 $HOME/.netrc

  # Git requires our "name" and email address -- use GitHub handle
  git config user.email "$GITHUB_ACTOR@users.noreply.github.com"
  git config user.name "$GITHUB_ACTOR"
  
  # Push to the current branch if PUSH_BRANCH hasn't been overriden
  : ${PUSH_BRANCH:=`echo "$GITHUB_REF" | awk -F / '{ print $3 }' `}
}

# This section only runs if there have been file changes
echo "Checking for uncommitted changes in the git working tree."
if ! git diff --quiet
then 
  git_setup
  git checkout $PUSH_BRANCH
  git add .
  git commit -m "[bot] recompile lists | $now"
  git push --set-upstream origin $PUSH_BRANCH
else 
  echo "Working tree clean. Nothing to commit."
fi