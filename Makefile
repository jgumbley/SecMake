#export API_KEY=$(shell cat api_key.txt)

.DEFAULT_GOAL := ux

define success
	@tput setaf 2; \
	echo ""; \
	owls="🦉 🦆 🦢 🐦 🦜"; \
	n=$$(expr $$(od -An -N2 -tu2 /dev/urandom | tr -d ' ') % 5 + 1); \
	owl=$$(echo $$owls | cut -d' ' -f$$n); \
	printf "%s > \033[33m%s\033[0m completed [OK]\n" "$$owl" "$(@)"; \
	tput sgr0;
endef

ux: auth venv
	. venv/bin/activate && python test_chronicle_integration.py
	$(call success)

ext: venv
	. venv/bin/activate && \
	python src/viz/newviz.py
	$(call success)

unit: venv lint
	. venv/bin/activate && \
	python -m unittest discover -b
	$(call success)

venv:
	python3 -m venv venv
	. venv/bin/activate && \
	pip install -r requirements.txt
	$(call success)

auth:
	if gcloud auth application-default print-access-token 2>&1 | grep -q "Your default credentials were not found"; then \
		gcloud auth application-default login; \
	else \
		echo "Already authenticated"; \
	fi

cleanauth:
	rm -f ~/.config/gcloud/application_default_credentials.json

.PHONY: docs
docs:
	cd docs; make
	$(call success)

clean:
	rm -rf venv
	$(call success)

lint:
	echo "Linting not implemented yet"
	$(call success)