ROOT=/
PREFIX=/usr

install:
	python version.py > "dpres_signature/version.py"

	# Cleanup temporary files
	rm -f INSTALLED_FILES

	# Use Python setuptools
	python setup.py build ; python ./setup.py install -O1 --prefix="${PREFIX}" --root="${ROOT}" --record=INSTALLED_FILES

install3:
	python3 version.py > "dpres_signature/version.py"

	# Cleanup temporary files
	rm -f INSTALLED_FILES

	# Use Python setuptools
	python3 setup.py build ; python3 ./setup.py install -O1 --prefix="${PREFIX}" --root="${ROOT}" --record=INSTALLED_FILES

clean: clean-rpm
	find . -iname '*.pyc' -type f -delete
	find . -iname '__pycache__' -exec rm -rf '{}' \; | true

clean-rpm:
	# Cleanup temporary files
	rm -f INSTALLED_FILES
	rm -rf rpmbuild

