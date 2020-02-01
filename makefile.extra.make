

KBFS_DIR = "/run/user/1000/keybase/kbfs/public/mbarkhau/sbk/"


## Regen TOC in README.md
.PHONY: mdtoc
mdtoc:
	$(DEV_ENV)/bin/md_toc --in-place READMEv2.md gitlab


pdf_templates/%.pdf: pdf_templates/template.html pdf_templates/gen_pdf.py
	$(DEV_ENV_PY) pdf_templates/gen_pdf.py


doc/%.svg : doc/%.bob
	svgbob --output $@ $<

## Regen doc/*.bob -> doc/*.svg
.PHONY: static_files
static_files: \
		pdf_templates/a4_24.pdf \
		doc/sbk_overview.svg \
		doc/sbk_dataflow_diagram.svg \
		doc/sbk_dataflow_diagram_v2.svg \
		doc/sss_diagram_1.svg \
		doc/sss_diagram_2.svg \
		doc/sss_diagram_3.svg \
		doc/raw_share_diagram.svg \
		doc/share_diagram.svg
	cp pdf_templates/*.pdf $(KBFS_DIR)
	cp doc/*.svg $(KBFS_DIR)
	cp logo* $(KBFS_DIR)


.PHONY: sbk-live-workdir/sbklive.iso
sbk-live-workdir/sbklive.iso:
	rm -f sbk-live-workdir/iso_extract_unsquash.ok
	bash sbk-live-remaster.sh

	# dd status=progress if=sbk-live-workdir/sbklive.iso of=/dev/sdx


## Create release iso
## createds venv with validated dependencies
.PHONY: release
release:
	rm -rf $(ENV_PREFIX)/sbk_release_py37/;
	$(CONDA_BIN) create --yes --name sbk_release_py37 python=3.7;
	$(ENV_PREFIX)/sbk_release_py37/bin/python -m pip install -r requirements/pypi.txt;


## Create a remastered iso based on tails
##
## Based on https://tails.boum.org/contribute/build/#index5h1
.PHONY: remaster
remaster:
	bash sbk-live-remaster.sh


## Add sign-off to requirements/pypi.txt
##
## When you have verified that a dependency is safe to use,
## mark it as such and add the hash of the safe dependency.
.PHONY: signoff-deps
signoff-deps:
	$(DEV_ENV)/bin/pipdeptree --reverse \
		| sed 's!^\s\{1,\}-\s!!g' \
		| sed 's!\[requires:.\{1,\}!!g'
	$(DEV_ENV)/bin/hashin argon2-cffi --python-version 3.7 -r requirements/pypi.txt


.PHONY: aspell
aspell:
	aspell -l en-uk -c READMEv2.md

