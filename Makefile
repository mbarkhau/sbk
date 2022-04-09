
PACKAGE_NAME := sbk

# This is the python version that is used for:
# - `make fmt`
# - `make ipy`
# - `make lint`
# - `make devtest`
DEVELOPMENT_PYTHON_VERSION := python=3.10

# These must be valid (space separated) conda package names.
# A separate conda environment will be created for each of these.
#
# Some valid options are:
# - python=2.7
# - python=3.5
# - python=3.6
# - python=3.7
# - pypy2.7
# - pypy3.5
SUPPORTED_PYTHON_VERSIONS := python=3.10 python=3.8

include Makefile.bootstrapit.make

## -- Extra/Custom/Project Specific Tasks --


## Regen TOC in README.md
.PHONY: mdtoc
mdtoc:
	$(DEV_ENV)/bin/md_toc --in-place READMEv2.md gitlab


pdf_templates/%.pdf: \
		src/sbk/assets/nostroke*.png \
		pdf_templates/share_template.html \
		pdf_templates/auth_template.html \
		pdf_templates/grid_template.html \
		pdf_templates/gen_pdf.py
	$(DEV_ENV_PY) pdf_templates/gen_pdf.py $@
	cp $@ src/sbk/assets/


svg2png := inkscape --without-gui --export-area-page --file

res = $(subst .png,,$(subst landingpage/,,$(subst src/sbk/assets/,,$(subst logo_,,$(subst nostroke_,,$(subst favico_,,$@))))))


src/sbk/assets/logo%.png: src/sbk/assets/logo.svg
	$(svg2png) src/sbk/assets/logo.svg --export-png $@ -w $(res)


src/sbk/assets/nostroke_logo%.png: src/sbk/assets/logo.svg
	cat src/sbk/assets/logo.svg \
		| sed "s/stroke-width:32/stroke-width:0/g" \
		> src/sbk/assets/nostroke_logo.svg
	$(svg2png) src/sbk/assets/nostroke_logo.svg --export-png $@ -w $(res)


src/sbk/assets/favico_%.png: src/sbk/assets/logo.svg
	$(svg2png) src/sbk/assets/logo.svg --export-png $@ -w $(res)


.PHONY: assets
assets: \
		src/sbk/assets/logo_128.png \
		src/sbk/assets/logo_256.png \
		src/sbk/assets/logo_1024.png \
		src/sbk/assets/nostroke_logo_64.png \
		src/sbk/assets/nostroke_logo_128.png \
		src/sbk/assets/nostroke_logo_256.png \
		src/sbk/assets/nostroke_logo_1024.png \
		src/sbk/assets/favico_24.png \
		src/sbk/assets/favico_32.png \
		src/sbk/assets/favico_48.png \
		src/sbk/assets/favico_96.png \
		src/sbk/assets/nostroke_logo_256.png \
		landingpage/favico_24.png \
		landingpage/favico_32.png \
		landingpage/favico_48.png \
		landingpage/favico_96.png \
		pdf_templates/share_a4.pdf \
		pdf_templates/share_letter.pdf \
		pdf_templates/auth_a4.pdf \
		pdf_templates/auth_letter.pdf \
		pdf_templates/grid_a4.pdf \
		pdf_templates/grid_letter.pdf
	cp src/sbk/assets/*.png landingpage/
	cp pdf_templates/*.pdf landingpage/


## Create release iso
## createds venv with validated dependencies
.PHONY: release
release:
	bash scripts/gen_iso.sh


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
	aspell -l en-us -c README.md


.PHONY: debug_gui
debug_gui:
	SBK_MEM_PERCENT=1 \
	SBK_DEBUG_RANDOM=DANGER \
	SBK_DEBUG_RAW_SALT_LEN=1 \
	SBK_DEBUG_BRAINKEY_LEN=2 \
	SBK_NUM_SHARES=3 \
	SBK_THRESHOLD=2 \
	SBK_KDF_KDF_T=1 \
	$(DEV_ENV_PY) -m sbk.gui


.PHONY: debug_cli
debug_cli:
	SBK_MEM_PERCENT=1 \
	SBK_DEBUG_RANDOM=DANGER \
	SBK_DEBUG_RAW_SALT_LEN=1 \
	SBK_DEBUG_BRAINKEY_LEN=2 \
	SBK_NUM_SHARES=3 \
	SBK_THRESHOLD=2 \
	SBK_KDF_KDF_T=1 \
	$(DEV_ENV_PY) -m sbk.cli create --yes-all


.PHONY: serve_doc
serve_doc:
	$(DEV_ENV_PY) -m http.server --directory doc/ 8080


.PHONY: serve_landingpage
serve_landingpage:
	$(DEV_ENV_PY) -m http.server --directory landingpage/ 8080


.PHONY: landingpage_sync
landingpage_sync:
	rsync landingpage/*.* root@vserver:/var/www/html/sbk/

	ssh root@vserver "mkdir -p /var/www/html/sbk/static/"
	ssh root@vserver "mkdir -p /var/www/html/sbk/pdf_templates/"

	rsync landingpage/static/*.* root@vserver:/var/www/html/sbk/static/
	rsync pdf_templates/*.pdf root@vserver:/var/www/html/sbk/pdf_templates/

	ssh root@vserver "chown -R mbarkhau:mbarkhau /var/www/html/sbk/"
