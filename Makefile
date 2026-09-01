PYTHON ?= /usr/bin/python

test:
	$(PYTHON) -m pytest -q

api:
	PYTHONPATH=backend $(PYTHON) -m uvicorn app.main:app --reload

migrate:
	$(PYTHON) -m alembic upgrade head

doctor:
	PYTHONPATH=backend $(PYTHON) -m app.cli doctor

test-apk:
	PYTHONPATH=backend $(PYTHON) scripts/build_test_app.py

analyze: test-apk
	PYTHONPATH=backend $(PYTHON) -m app.cli analyze analysis/test-apks/AndroidSecForge-TestApp.apk

.PHONY: test api migrate doctor test-apk analyze
