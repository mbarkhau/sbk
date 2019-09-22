

.PHONY: sbk-live-workdir/sbklive.iso
sbk-live-workdir/sbklive.iso:
	rm -f sbk-live-workdir/iso_extract_unsquash.ok
	bash sbk-live-remaster.sh

	# dd status=progress if=sbk-live-workdir/sbklive.iso of=/dev/sdx


KBFS_DIR = "/run/user/1000/keybase/kbfs/public/mbarkhau/sbk/"


doc/%.svg : doc/%.bob
	svgbob --output $@ $<

svgbob_images: \
		doc/sbk_dataflow_diagram.svg \
		doc/sss_diagram_1.svg \
		doc/sss_diagram_2.svg \
		doc/sss_diagram_3.svg
	cp doc/*.svg $(KBFS_DIR)