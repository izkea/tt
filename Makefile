merge:
	git fetch upstream
	git merge upstream/master

push:
	git push --tags
