ROOT=/
PREFIX=/usr

install:
	python version.py > "dpres_signature/version.py"

	# Use Python setuptools
	python setup.py build ; python ./setup.py install -O1 --prefix="${PREFIX}" --root="${ROOT}" --record=INSTALLED_FILES
	cat INSTALLED_FILES | sed 's/^/\//g' >> INSTALLED_FILES

test: 
	py.test -svvl --maxfail=9999 --junitprefix=dpres_signature --junitxml=junit.xml tests

coverage:
	py.test tests --cov=dpres_signature --cov-report=html
	coverage report -m
	coverage html
	coverage xml

clean: clean-rpm
	find . -iname '*.pyc' -type f -delete
	find . -iname '__pycache__' -exec rm -rf '{}' \; | true

clean-rpm:
	# Cleanup temporary files
	rm -f INSTALLED_FILES
	rm -rf rpmbuild

rpm: clean-rpm
	create-archive.sh
	preprocess-spec-m4-macros.sh include/rhel6
	build-rpm.sh

.e2e/ansible:
	git clone https://source.csc.fi/scm/git/pas/ansible-preservation-system .e2e/ansible

.e2e/ansible-fetch: .e2e/ansible
	cd .e2e/ansible ; \
		git fetch ; \
		git checkout master ; \
		git reset --hard origin/master ; \
		git clean -fdx ; \
		git status

e2e-localhost-cleanup: .e2e/ansible-fetch
	cd .e2e/ansible ; ansible-playbook -i inventory/localhost e2e-pre-test-cleanup.yml
