.SILENT:

all: clean
	cargo build
	ln -s ./target/debug/pe-parser
	chmod +x ./pe-parser

clean:
	rm -f pe-parser

validation-pe-tests: all
	python3 -m tests ValidatingPeTestCases -f

import-dll-tests: all
	python3 -m tests ImportDllTestCases -f

import-function-tests: all
	python3 -m tests ImportFunctionTestCases -f

export-function-tests: all
	python3 -m tests ExportFunctionTestCases -f

all-tests: validation-pe-tests import-dll-tests import-function-tests export-function-tests
