#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root/with sudo";
	exit 1;
fi

set -e;
# set -x;

SBK_ELECTRUM_VERSION="3.3.8";

# Checksums from
# https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/SHA256SUMS

SBK_ISO_FILE="debian-live-10.0.0-amd64-standard.iso";
SBK_ISO_CHECKSUM="9505a0ef7f336955a48f2b72f175e3afeb611e17a44aafa11181a4b6288654cb";

# SBK_ISO_FILE="debian-live-10.0.0-amd64-gnome.iso";
# SBK_ISO_CHECKSUM="0d44727dbc9155bf8f1d7068ef74a08c8ad7f7068d4acb9d06b510bafd52f72f";

# SBK_ISO_FILE="debian-live-10.0.0-amd64-lxde.iso";
# SBK_ISO_CHECKSUM="8db0828ac1accd7959785f43d3fdfe11e00a1f159902347099d637f5ed51d2f1";

sbk_datadir="$PWD/sbk-live-data";
sbk_workdir="$PWD/sbk-live-workdir";

cp "${sbk_datadir}/.config" "${sbk_workdir}"
cp "${sbk_datadir}/config.conf" "${sbk_workdir}"

SBK_ISOURL="https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/$SBK_ISO_FILE";

sbk_isopath="${sbk_workdir}/$SBK_ISO_FILE";
sbk_isochecksum_path="${sbk_isopath}.sha256sum";

SBK_ELECTRUM_GPGFILE="Electrum-${SBK_ELECTRUM_VERSION}.tar.gz.asc";
SBK_ELECTRUM_FILE="Electrum-${SBK_ELECTRUM_VERSION}.tar.gz";

sbk_electrumpath="${sbk_workdir}/$SBK_ELECTRUM_FILE";
sbk_electrumurl="https://download.electrum.org/${SBK_ELECTRUM_VERSION}/$SBK_ELECTRUM_FILE";

sbk_whl_file=$(cd dist;ls -t sbk*none-any.whl | head -n 1);

function su {
	sudo -u $SUDO_USER $@;
}

su mkdir -p ${sbk_workdir};

if ! [ -f ${sbk_electrumpath} ]; then
	su wget -O "${sbk_electrumpath}" "${sbk_electrumurl}";
fi

su cp ${sbk_datadir}/$SBK_ELECTRUM_GPGFILE ${sbk_workdir}/$ELECTRUMCHECKSUMFILE;
su gpg --import ${sbk_datadir}/ThomasV.asc;
su gpg --verify ${sbk_workdir}/$SBK_ELECTRUM_GPGFILE;

if ! [ -f ${sbk_isopath} ]; then
	su wget -O "${sbk_isopath}.unverified" "$SBK_ISOURL";
	echo "${SBK_ISO_CHECKSUM} ${sbk_isopath}.unverified" > ${sbk_isochecksum_path};
	sha256sum --check ${sbk_isochecksum_path};
	mv ${sbk_isopath}.unverified ${sbk_isopath};
	echo "${SBK_ISO_CHECKSUM} ${sbk_isopath}" > ${sbk_isochecksum_path};
	chown "$SUDO_USER:" ${sbk_isochecksum_path};
fi

echo "downloads complete";

# dd status=progress if=/home/mbarkhau/workspace/live-remaster/SBK-Live.iso of=/dev/sd

# apt-get purge -y `dpkg -l | awk ' { print $2 } ' | grep '\-doc$'`
# apt-get purge -y `dpkg -l | awk ' { print $2 } ' | grep '^aspell-'`

# apt-get purge -y aspell hunspell dictionaries-common ispell aspell-no live-boot-doc live-config-doc
# apt-get autoclean


export JLdir=/usr/local/JLIVECD
JLdir=/usr/local/JLIVECD
cd /usr/local/JLIVECD

set -a

. ./defconf.sh
. ./funcs.sh
. /usr/local/JLIVECD/.config

set +a

chkroot

if [ -f "${JL_lockF}" ]; then
	exit 1;
fi
touch "${JL_lockF}"
trap_with_arg finish SIGTERM EXIT SIGQUIT

mkdir -p "${JL_logdirtmp}";

export live_os="debian";

# jlcd_start()

	export livedir=
	export liveconfigfile=
	export edit=
	JL_terminal1=$TERMINAL1
	JL_terminal2=$TERMINAL2
	command -v "$JL_terminal1" >/dev/null 2>&1 || JL_terminal1='x-terminal-emulator'
	command -v "$JL_terminal2" >/dev/null 2>&1 || JL_terminal2='xterm'

	maindir="$PWD"
	livedir=${sbk_workdir};
	livedir=$(sanit_path "$livedir")


	isopath="$sbk_isopath"
    IMAGENAME="$(get_iso_label "$isopath")"

    # Debian specific
    JL_debian=true;
    JL_casper=live
    JL_squashfs="$JL_casper"/filesystem.squashfs
    JL_resolvconf=var/run/NetworkManager/resolv.conf #must not start with /

	cd "$livedir";

    if [ -f sbklive_x64.iso ]; then
		mv sbklive_x64.iso sbklive_x64_$(ls -1 sbklive*.iso | wc -l).iso;
	fi

    # NOTE: Uncomment this line if you want don't want to
    #   rebuild from scratch every time.
    rm -f "iso_extract_unsquash.ok"

    if ! [ -f "iso_extract_unsquash.ok" ]; then
		rm -rf extracted;
		rm -rf squashfs-root;
		rm -rf edit;

		mount -o loop "$isopath" mnt || wrn_out "failed to mount iso."
	    rsync --exclude=/"$JL_squashfs" -a mnt/ extracted || { umount mnt || umount -lf mnt; err_exit "rsync failed"; }
        unsquashfs -f mnt/"$JL_squashfs" || { umount mnt || umount -lf mnt; err_exit "unsquashfs failed"; }
		mv -fT squashfs-root edit || { umount mnt || umount -lf mnt; err_exit "couldn't move squashfs-root."; }
		umount mnt || umount -lf mnt;
		touch "iso_extract_unsquash.ok";
	fi

	cd "$maindir"
	liveconfigfile="$livedir/.config"
	touch "$liveconfigfile"
	chmod 777 "$liveconfigfile"
	edit=$(abs_path "$livedir/edit")/ #must end with a slash
	set -a
	if [ -f "$livedir/$JL_sconf"  ]; then
		. "$livedir/$JL_sconf"
	fi
	set +a

    osmode="$live_os"
    update_prop_val "$JL_mdpn" "$osmode" "$liveconfigfile" "operating mode (override not possible)"
    update_prop_val "$JL_inpn" "$IMAGENAME" "$liveconfigfile" "Image label (no override for archlinux)"

	if [ "$CHROOT" = "" ]; then
		CHROOT='chroot ./edit'
	elif ! command -v $CHROOT >/dev/null 2>&1; then
		wrn_out "invalid chroot command: $CHROOT\n--- falling back to default chroot."
		CHROOT='chroot ./edit'
	elif ! echo "$CHROOT" |grep -qE '^[[:blank:]]*s{0,1}chroot[[:blank:]]+[^[:blank:]]'; then
		wrn_out "invalid chroot command: $CHROOT\n--- falling back to default chroot."
		CHROOT='chroot ./edit'
	fi

	msg_out "chroot command: $CHROOT"

	cdname="$(get_prop_val "$JL_dnpn" "$liveconfigfile")"
	iso="$(echo "$cdname" |tail -c 5)"
	iso="$(to_lower "$iso")"
	if [ "$iso" = ".iso" ]; then
	  cdname="$(echo "$cdname" | sed 's/....$//')"
	fi
	if [ "$cdname" = "" ]; then
		cdname="New-Disk"
		msg_out "Using 'New-Disk' as cd/dvd name"
	else
		msg_out "Using '$cdname' as cd/dvd name"
	fi
	update_prop_val "$JL_dnpn" "$cdname" "$liveconfigfile" "ISO image name without .iso"

	##############################Copy some required files#####################################################################
	cp preparechroot "$livedir"/edit/prepare
	cp help "$livedir"/edit/help
	cd "$livedir"
	msg_out "Entered into directory $livedir"
	##############################Enable network connection####################################################################
    cp -L /etc/hosts edit/.
    cp -L /etc/resolv.conf edit/.
	refresh_network
    #JLopt -rn
	##############################cache management########################################################################
	msg_out "Cache Management starting. Moving package files to cache dir"
	cd "$livedir"
	if [ -d "debcache" ]; then
        if $JL_archlinux; then
            echo dummy123456 > debcache/dummy123456.pkg.tar.xz
            mv -f debcache/*.xz edit/var/cache/pacman/pkg/
            msg_out "pkg files moved. Cache Management complete!"
        else
            echo dummy123456 > debcache/dummy123456.deb
            mv -f debcache/*.deb edit/var/cache/apt/archives
            msg_out "deb files moved. Cache Management complete!"
        fi
	fi
	#more cache
	if [ -d mydir ] && [ -d edit ]; then
		mv -f mydir edit/
	elif [ -d edit ]; then
		mkdir -p edit/mydir
	fi
	chmod 777 edit/mydir
	msg_out 'use edit/mydir to store files that are not supposed to be included in the resultant livecd. This directory content persists and thus you can keep source packages and other files here. An octal 777 permission is set for this directory, thus no root privilege required to copy files.'
	##############################Create chroot environment and prepare it for use#############################################
	msg_out "Detecting access control state"
	if xhost | grep 'access control enabled' >/dev/null; then
		bxhost='-'
		msg_out 'Access control is enabled'
	else
		bxhost='+'
		msg_out 'Access control is disabled'
	fi

	xh=$(get_prop_val "$JL_xhpn" "$liveconfigfile")
	update_prop_val "$JL_xhpn" "$xh" "$liveconfigfile" "Whether to prevent GUI apps to run."
	if [ "$xh" != Y ] && [ "$xh" != y ]; then
		xhost + >/dev/null && msg_out "access control disabled"
	else
		xhost - && msg_out "access control enabled"
	fi

    check_space_changed=false
    if ! $JL_archlinux; then
        msg_out "installing updarp in chroot ..."
        cp "$JLdir"/updarp edit/usr/bin/updarp
    else
        if grep -q '^[[:blank:]]*CheckSpace' edit/etc/pacman.conf; then
            sed -i.bak 's/^[[:blank:]]*CheckSpace/#&/' edit/etc/pacman.conf
            check_space_changed=true
        fi
    fi
	mount_fs

    msg_out "installing electrum";
	tar xzf $sbk_electrumpath
    rm -rf edit/usr/local/electrum/;
	mkdir -p edit/usr/local/electrum/;
	mv "Electrum-${SBK_ELECTRUM_VERSION}"/* edit/usr/local/electrum/;
	# ln edit/usr/local/electrum/run_electrum edit/bin/electrum

 	# xterm -e "$SHELL -c '$CHROOT /prepare ;HOME=/root LC_ALL=C $CHROOT;exec $SHELL'" 2>/dev/null
 	# $CHROOT /prepare $prepare_args;

 	$CHROOT apt-get update

 	$CHROOT apt-get install -y lxde-core libzbar-dev;

    # TODO: validate dependencies and use hashes in requirements/pypi.txt
 	$CHROOT apt-get install -y \
 		python3-pip \
 		python3-pyqt5 \
 		python3-dnspython \
 		python3-pyaes \
 		python3-ecdsa \
 		python3-qrcode \
 		python3-protobuf \
		python3-jsonrpclib-pelix \
		python3-aiohttp \
		python3-certifi;

 	$CHROOT python3 -m pip install /usr/local/electrum/;

	mkdir -p edit/usr/local/sbk/;
    mkdir -p edit/usr/local/share/applications/
    mkdir -p edit/usr/local/share/icons/

	cp ../dist/${sbk_whl_file} edit/usr/local/sbk/;

	cp ../logo_128.png edit/usr/share/icons/sbk.png;
    cp edit/usr/local/electrum/electrum/gui/icons/electrum.png edit/usr/share/icons/;

    cp ../sbk-live-data/sbk_repl.desktop edit/usr/local/share/applications/;
    cp edit/usr/local/electrum/electrum.desktop edit/usr/local/share/applications/;

    chmod 644 edit/usr/share/icons/*.png

 	$CHROOT python3 -m pip install /usr/local/sbk/${sbk_whl_file};

    # NOTE: it does not appear that removing any of these has an
    #   effect on image size. The base image is perhaps not modified
    #   at all and instead there is some kind of overlay on the file
    #   system.

 	# HOME=/root LC_ALL=C $CHROOT bash

 	# $CHROOT apt-get remove -y "doc-debian"
 	# $CHROOT apt-get remove -y "debian-faq"
 	# $CHROOT apt-get remove -y "debian-faq-*"
 	# $CHROOT apt-get remove -y "openssh-*"

 	# $CHROOT apt-get remove -y "libreoffice-*"
 	# $CHROOT apt-get remove -y "doc-linux-text"
 	# $CHROOT apt-get remove -y "dictionaries"
 	# $CHROOT apt-get remove -y "aspell"
 	# $CHROOT apt-get remove -y "aspell-*"
 	# $CHROOT apt-get remove -y "hunspell-*"
 	# $CHROOT apt-get remove -y "myspell-*"
 	# $CHROOT apt-get remove -y "mythes-*"
 	# $CHROOT apt-get remove -y "thunderbird"
 	# $CHROOT apt-get remove -y "fonts-noto-*"
 	# $CHROOT apt-get remove -y "ppp*"

 	# $CHROOT apt-get autoremove -y
 	# $CHROOT apt-get clean -y
 	# $CHROOT bash -c "rm -f /var/lib/apt/lists/*_Packages"

    $CHROOT adduser user --gecos GECOS --home /home/user --disabled-password
    $CHROOT adduser user sudo

	$CHROOT mkdir -p /home/user/Desktop

    $CHROOT ln -s /usr/local/share/applications/electrum.desktop /home/user/Desktop/electrum.desktop
    $CHROOT ln -s /usr/local/share/applications/sbk_repl.desktop /home/user/Desktop/sbk_repl.desktop

	$CHROOT chown -R user: /home/user

 	# HOME=/root LC_ALL=C $CHROOT bash

 	# skipped rebuild_initramfs
  	msg_out "edit/home kept as it is"

    ################################# Changing back some configs #################################################
    if ! $JL_archlinux; then
        msg_out "removing updarp ..."
        rm edit/usr/bin/updarp
    elif $check_space_changed; then
        sed -i.bak 's/^##*[[:blank:]]*\(CheckSpace\)/\1/' edit/etc/pacman.conf
    fi
	msg_out 'Restoring access control state'
	xhost $bxhost | sed 's/^/\n*** /' && msg_out "xhost restored to initial state."  #leave this variable unquoted

	##################################Cache management############################################################
	msg_out "Cache Management starting. Moving package files to local cache dir"
	cd "$livedir"
	if [ ! -d "debcache" ]; then
	  mkdir debcache
	fi
    if $JL_archlinux; then
        echo dummy123456 > edit/var/cache/pacman/pkg/dummy123456.pkg.tar.xz
        mv -f edit/var/cache/pacman/pkg/*.xz debcache
        msg_out "pkg files moved. Cache Management complete!"
        $CHROOT pacman -Scc --noconfirm #cleaning cache
    else
        echo dummy123456 > edit/var/cache/apt/archives/dummy123456.deb
        mv -f edit/var/cache/apt/archives/*.deb debcache
        msg_out "deb files moved. Cache Management complete!"
    fi
	##################################Cleaning...#########################################
	kerver=$(uname -r)
	cd "$livedir" #exported from jlcd_start
	rm -f edit/run/synaptic.socket
	$CHROOT apt-get clean
	if [ -d edit/mydir ]; then
		mv -f edit/mydir ./
	fi
	rm -rf edit/tmp/*
	###############################Post Cleaning#####################################################################
	msg_out "Cleaning system"
	rm -f edit/prepare
	rm -f edit/help
	msg_out "System Cleaned!"
    ############################# Prepare to create CD/DVD####################################################################
	fastcomp=$(get_prop_val "$JL_fcpn" "$liveconfigfile" "Use fast compression (ISO size may become larger)" "$timeout")
	update_prop_val "$JL_fcpn" "$fastcomp" "$liveconfigfile" "y: Fast compression, larger image size. n: smaller image but slower"
	#check for uefi
	uefi=$(get_prop_val "$JL_ufpn" "$liveconfigfile" "Want UEFI image" "$timeout")
	update_prop_val "$JL_ufpn" "$uefi" "$liveconfigfile" "Whether the image to be built is a UEFI image"
	#check for nhybrid
	nhybrid=$(get_prop_val "$JL_hbpn" "$liveconfigfile" "Prevent hybrid image" "$timeout")
	update_prop_val "$JL_hbpn" "$nhybrid" "$liveconfigfile" "Whether to prevent building hybrid image."
	msg_out "FASTCOMPRESSION=$fastcomp\n*** UEFI=$uefi\n*** NOHYBRID=$nhybrid"
	msg_out "Updating some required files..."
	###############################Create CD/DVD##############################################################################
	cd "$livedir"
    if ! $JL_archlinux; then
    	touch extracted/"$JL_casper"/filesystem.manifest;
        chmod +w extracted/"$JL_casper"/filesystem.manifest 2>/dev/null
        $CHROOT dpkg-query -W --showformat='${Package} ${Version}\n' > extracted/"$JL_casper"/filesystem.manifest
    fi
	#no more CHROOT
	umount_fs
    if ! $JL_archlinux; then
        cp extracted/"$JL_casper"/filesystem.manifest extracted/"$JL_casper"/filesystem.manifest-desktop
        sed -i '/ubiquity/d' extracted/"$JL_casper"/filesystem.manifest-desktop
        sed -i "/$JL_casper/d" extracted/"$JL_casper"/filesystem.manifest-desktop
    fi
    rm -f extracted/"$JL_squashfs"
	msg_out "Deleted old squashfs.."
	msg_out "Rebuilding squashfs.."
	if [ "$fastcomp" = Y ] || [ "$fastcomp" = y ];then
	  msg_out "Using fast compression. Size may become larger"
	  mksquashfs edit extracted/"$JL_squashfs" -b 1048576 -e edit/boot || err_exit "mksquashfs failed!"
	else
	  msg_out "Using exhaustive compression. Size may become lesser"
	  mksquashfs edit extracted/"$JL_squashfs" -comp xz || err_exit "mksquashfs failed!"
      # mksquashfs edit extracted/"$JL_squashfs" -b 1048576 -e edit/boot || err_exit "mksquashfs failed!"
	fi
    if ! $JL_archlinux; then
        printf $(du -sx --block-size=1 edit | cut -f1) > extracted/"$JL_casper"/filesystem.size
        cd extracted
        msg_out "Updating md5sums"
        if [ -f "MD5SUMS" ]; then
          rm MD5SUMS
          find -type f -print0 | xargs -0 md5sum | grep -v isolinux/boot.cat | tee MD5SUMS
        fi
        if [ -f "md5sum.txt" ]; then
          rm md5sum.txt
          find -type f -print0 | xargs -0 md5sum | grep -v isolinux/boot.cat | tee md5sum.txt
        fi
    else
        cd extracted
        msg_out "Updating md5sums"
        md5sum "$JL_squashfs" > "$(dirname "$JL_squashfs")/airootfs.md5"
    fi
	msg_out "Creating the image"

	if [ "$uefi" = Y ] || [ "$uefi" = y ];then
        if ! $JL_archlinux; then
            efi_img=boot/grub/efi.img
        else
            efi_img=EFI/archiso/efiboot.img
        fi
		genisoimage -U -A "$IMAGENAME" -V "$IMAGENAME" -volset "$IMAGENAME" -J -joliet-long -D -r -v -T -o ../"$cdname".iso -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table -eltorito-alt-boot -e "$efi_img" -no-emul-boot . && msg_out 'Prepared UEFI image'
		uefi_opt=--uefi
	else
		genisoimage -D -r -V "$IMAGENAME" -cache-inodes -J -no-emul-boot -boot-load-size 4 -boot-info-table -l -b isolinux/isolinux.bin -c isolinux/boot.cat -o ../"$cdname".iso .
		uefi_opt=
	fi
	if [ "$nhybrid" != Y ] && [ "$nhybrid" != y ]; then
		isohybrid $uefi_opt ../"$cdname".iso && msg_out "Converted to hybrid image" || wrn_out "Could not convert to hybrid image"
	fi
	cd ..
	msg_out "Finalizing image"
	chmod 777 "$cdname".iso
	msg_out ".All done. Check the result."
	exit 0
