merge:
	git fetch upstream --no-tags
	git merge upstream/master

push:
	git push --tags
