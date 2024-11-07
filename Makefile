clean:
	rm -rf cosmic-ray.sqlite cosmic-report.html

install: .venv
	pip install -r requirements.txt

test:
	pytest

cosmic-ray.sqlite:
	cosmic-ray init cosmic-ray.toml $@
	cosmic-ray --verbosity=INFO baseline cosmic-ray.toml
	cosmic-ray exec cosmic-ray.toml $@

cosmic-ray.html: cosmic-ray.sqlite
	cr-html cosmic-ray.sqlite > $@

.venv:
	python -mvenv .venv
