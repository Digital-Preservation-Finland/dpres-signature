ROOT=/
PREFIX=/usr

install:
	python version.py > "dpres_signature/version.py"

	# Cleanup temporary files
	rm -f INSTALLED_FILES

	# Use Python setuptools
	python setup.py build ; python ./setup.py install -O1 --prefix="${PREFIX}" --root="${ROOT}" --record=INSTALLED_FILES
	cat INSTALLED_FILES | sed 's/^/\//g' >> INSTALLED_FILES

install3:
	python3 version.py > "dpres_signature/version.py"

	# Cleanup temporary files
	rm -f INSTALLED_FILES

	# Use Python setuptools
	python3 setup.py build ; python3 ./setup.py install -O1 --prefix="${PREFIX}" --root="${ROOT}" --record=INSTALLED_FILES
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
	preprocess-spec-m4-macros.sh include/rhel7
	build-rpm.sh

rpm3: clean-rpm
	create-archive.sh
	preprocess-spec-m4-macros.sh include/rhel8
	build-rpm.sh
