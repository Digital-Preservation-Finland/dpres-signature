test: 
	py.test -svvl --maxfail=9999 --junitprefix=dpres_signature --junitxml=junit.xml tests

coverage:
	py.test tests --cov=dpres_signature --cov-report=html
	coverage report -m
	coverage html
	coverage xml
