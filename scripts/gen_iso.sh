#!/bin/bash

# https://slai.github.io/posts/customising-ubuntu-live-isos-with-docker/

# apt-get install p7zip-full grub2-common mtools xorriso squashfs-tools-ng

mkdir -p sbk-live-build
cd sbk-live-build

# ISO_PATH=tails-amd64-4.18.iso
ISO_PATH=ubuntu-20.04.2.0-desktop-amd64.iso

if [[ ! -f $ISO_PATH ]]; then
    curl "https://releases.ubuntu.com/20.04.2.0/ubuntu-20.04.2.0-desktop-amd64.iso" \
    --location --continue-at - --output $ISO_PATH;
    echo "93bdab204067321ff131f560879db46bee3b994bf24836bb78538640f689e58f *${ISO_PATH}" \
        | shasum -a 256 --check;
fi

# create a directory to build the ISO from
rm -rf iso
mkdir -p iso
rm -f ubuntulive.iso
rm -f newfilesystem*

# rm -f filesystem.squashfs
# 7z e -o. "$ISO_PATH" casper/filesystem.squashfs

# sqfs2tar filesystem.squashfs | docker import - "ubuntulive:base"


cat <<'EOF' > 10_ubuntu-settings.gschema.override
###################
# global settings #
###################

[org.gnome.evolution-data-server.calendar]
notify-with-tray=false

[org.gnome.shell]
favorite-apps = ['org.gnome.Nautilus.desktop', 'gnome_region_and_lang.desktop', 'electrum_sbk.desktop']

[org.gnome.desktop.background]
picture-uri = 'file:///usr/share/backgrounds/ubuntu-default-greyscale-wallpaper.png'

[org.gnome.desktop.screensaver]
picture-uri = 'file:///usr/share/backgrounds/ubuntu-default-greyscale-wallpaper.png'

[org.gnome.desktop.sound]
theme-name = 'Yaru'
input-feedback-sounds = true

[org.gnome.desktop.session]
session-name = "ubuntu"

[org.gnome.Epiphany]
default-search-engine = 'DuckDuckGo'
search-engines = [('DuckDuckGo', 'https://duckduckgo.com/?q=%s&amp;t=canonical', '!ddg'), ('Google', 'https://www.google.com/search?client=ubuntu&channel=es&q=%s', '!g'), ('Bing', 'https://www.bing.com/search?q=%s', '!b')]

[org.gnome.crypto.pgp]
keyservers = ['hkp://keyserver.ubuntu.com:11371', 'ldap://keyserver.pgp.com']

[org.onboard]
layout = 'Compact'
theme = 'Nightshade'
key-label-font = 'Ubuntu'
key-label-overrides = ['RWIN::super-group', 'LWIN::super-group']
xembed-onboard = true

[org.onboard.window]
docking-enabled = true
force-to-top = true

[org.gnome.rhythmbox.encoding-settings]
media-type-presets = {'audio/x-vorbis':'Ubuntu', 'audio/mpeg':'Ubuntu'}

[org.gnome.settings-daemon.plugins.power]
sleep-inactive-ac-timeout = 0

# for GDM/DM
# FIXME: move to :Ubuntu-Greeter once upstream supports this, see LP: #1788010
[org.gnome.desktop.interface:GNOME-Greeter]
gtk-theme = "Yaru"
icon-theme = "Yaru"
cursor-theme = "Yaru"
font-name = "Ubuntu 11"
monospace-font-name = "Ubuntu Mono 13"

[org.gnome.login-screen]
logo='/usr/share/plymouth/ubuntu-logo.png'

##################################
# ubuntu common session settings #
##################################

[org.gnome.shell:ubuntu]
always-show-log-out = true

[org.gnome.desktop.background:ubuntu]
show-desktop-icons = true

[org.gnome.desktop.interface:ubuntu]
gtk-theme = "Yaru"
icon-theme = "Yaru"
cursor-theme = "Yaru"
font-name = "Ubuntu 11"
monospace-font-name = "Ubuntu Mono 13"
document-font-name = "Sans 11"
enable-hot-corners = false

[org.gtk.Settings.FileChooser:ubuntu]
sort-directories-first = true
startup-mode = 'cwd'

# Mirror G-S default experience (in overrides) compared to mutter default
# as we are using a G-S mode, the default overrides aren't used.
[org.gnome.mutter:ubuntu]
attach-modal-dialogs = true
edge-tiling = true
dynamic-workspaces = true
workspaces-only-on-primary = true
focus-change-on-pointer-rest = true

[org.gnome.desktop.peripherals.touchpad:ubuntu]
tap-to-click = true
click-method = 'default'

[org.gnome.desktop.wm.keybindings:ubuntu]
show-desktop = ['<Primary><Super>d','<Primary><Alt>d','<Super>d']
switch-applications = ['<Super>Tab']
switch-windows = ['<Alt>Tab']
switch-applications-backward = ['<Shift><Super>Tab']
switch-windows-backward = ['<Shift><Alt>Tab']

[org.gnome.desktop.wm.preferences:ubuntu]
button-layout = ':minimize,maximize,close'
titlebar-font = 'Ubuntu Bold 11'
titlebar-uses-system-font = false
action-middle-click-titlebar = 'lower'

[org.gnome.eog.ui:ubuntu]
sidebar = false

[org.gnome.Empathy.conversation:ubuntu]
theme = "adium"
theme-variant = "Normal"
adium-path = "/usr/share/adium/message-styles/ubuntu.AdiumMessageStyle"

[org.gnome.nautilus.desktop:ubuntu]
home-icon-visible = false

[org.gnome.nautilus.icon-view:ubuntu]
default-zoom-level = 'small'

[org.gnome.shell.extensions.desktop-icons:ubuntu]
icon-size = 'small'

[org.gnome.nautilus.preferences:ubuntu]
open-folder-on-dnd-hover = false

[org.gnome.rhythmbox.rhythmdb:ubuntu]
monitor-library = true

[org.gnome.rhythmbox.plugins:ubuntu]
active-plugins = ['alternative-toolbar', 'artsearch', 'audiocd','audioscrobbler','cd-recorder','daap','dbus-media-server','generic-player','ipod','iradio','mmkeys','mpris','mtpdevice','notification','power-manager']

[org.gnome.rhythmbox.plugins.alternative_toolbar:ubuntu]
display-type=1

[org.gnome.settings-daemon.plugins.power:ubuntu]
button-power = 'interactive'
button-sleep = 'suspend'
critical-battery-action = 'suspend'
power-button-action = 'interactive'

[org.gnome.settings-daemon.plugins.xsettings:ubuntu]
antialiasing = 'rgba'

[org.gnome.settings-daemon.plugins.print-notifications:ubuntu]
active = false

[org.gnome.settings-daemon.plugins.background:ubuntu]
active = false

[org.gnome.software:ubuntu]
first-run = false

[org.gnome.Terminal.Legacy.Settings:ubuntu]
theme-variant = 'dark'

##########################
# unity specific session #
##########################

[org.gnome.desktop.wm.preferences:Unity]
button-layout = 'close,minimize,maximize:'
mouse-button-modifier = '<Alt>'

[org.gnome.nautilus.desktop:Unity]
trash-icon-visible = false
volumes-visible = false

[org.cinnamon.desktop.media-handling:Unity]
automount = false
automount-open = false

[org.gnome.desktop.interface:Unity]
gtk-theme = "Ambiance"
icon-theme = "ubuntu-mono-dark"
cursor-theme = "DMZ-White"

[org.gnome.desktop.wm.keybindings:Unity]
maximize = ['<Primary><Super>Up','<Super>Up','<Primary><Alt>KP_5']
minimize = ['<Primary><Alt>KP_0']
move-to-corner-ne = ['<Primary><Alt>KP_Prior']
move-to-corner-nw = ['<Primary><Alt>KP_Home']
move-to-corner-se = ['<Primary><Alt>KP_Next']
move-to-corner-sw = ['<Primary><Alt>KP_End']
move-to-side-e = ['<Primary><Alt>KP_Right']
move-to-side-n = ['<Primary><Alt>KP_Up']
move-to-side-s = ['<Primary><Alt>KP_Down']
move-to-side-w = ['<Primary><Alt>KP_Left']
toggle-maximized = ['<Primary><Alt>KP_5']
toggle-shaded = ['<Primary><Alt>s']
unmaximize = ['<Primary><Super>Down','<Super>Down','<Alt>F5']

[org.gnome.settings-daemon.plugins.background:Unity]
active = true

[org.gnome.Terminal.Legacy.Settings:Unity]
headerbar = false

#############################################
# communitheme specific session for testers #
#############################################

[org.gnome.desktop.interface:communitheme]
cursor-theme = "communitheme"
icon-theme = "Suru"
gtk-theme = "Communitheme"

[org.gnome.desktop.sound:communitheme]
theme-name = "communitheme"
EOF

cat <<'EOF' > gnome_region_and_lang.desktop
[Desktop Entry]
Type=Application
Name=Region & Language
GenericName=Region & Language
Comment=Gnome Region & Language Settings
Exec=/usr/bin/gnome-control-center region
Path=/usr/bin/
Icon=/usr/share/icons/Yaru/256x256/apps/system-settings.png
Terminal=false
Categories=Settings;
Keywords=settings;language;keyboard
StartupNotify=true
EOF

cat <<'EOF' > electrum_sbk.desktop
[Desktop Entry]
Type=Application
Name=Electrum SBK
GenericName=Electrum SBK
Comment=Electrum Bitcoin Wallet
Exec=/usr/local/bin/electrum
Path=/usr/local/bin/
Icon=/opt/electrum_sbk.png
Terminal=false
Categories=Privacy;
Keywords=secure;security;privacy;private;bitcoin;sbk
StartupNotify=true
EOF

cat <<'EOF' > Dockerfile
# in the previous section, we imported the squashfs image into Docker as 'ubuntulive:base'
FROM ubuntulive:base

# set environment variables so apt installs packages non-interactively
# these variables will only be set in Docker, not in the resultant image
ENV DEBIAN_FRONTEND=noninteractive DEBIAN_PRIORITY=critical

RUN apt-get update

# install packages needed to repack the ISO (we'll be using this image to repack itself)
# grub-pc-bin needed for BIOS support
# grub-egi-amd64-bin and grub-efi-amd64-signed for EFI support
# grub2-common, mtools and xorriso are needed to build the ISO, xorriso is in universe repository

RUN add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe"
RUN apt-get install -y grub2-common grub-pc-bin grub-efi-amd64-bin grub-efi-amd64-signed mtools xorriso

# cleanup clutter from the desktop
RUN apt-get remove -y --purge thunderbird* firefox* libreoffice* hunspell* mythes* hyphen* ubiquity* rhythmbox* totem* remmina* gnome-font-viewer gnome-todo gnome-mahjongg gnome-sudoku gnome-mines aisleriot gnome-user-docs* gnome-getting-started-docs* transmission* yelp

# install electrum dependencies
RUN apt-get install -y libsecp256k1-0 python3-cryptography python3-pip python3-pyqt5
RUN python3 -m pip install argon2-cffi
RUN wget https://download.electrum.org/4.1.2/Electrum-4.1.2.tar.gz -O /opt/Electrum-4.1.2.tar.gz
RUN bash -c "cd /opt;tar xzf Electrum-4.1.2.tar.gz"
RUN bash -c "cd /opt/Electrum-4.1.2; python3 -m pip install .[gui]"

RUN apt-get autoremove -y && apt-get clean

RUN rm /usr/share/applications/org.gnome.Characters.desktop
RUN rm /usr/share/applications/gnome-language-selector.desktop

ADD gnome_region_and_lang.desktop /usr/share/applications/gnome_region_and_lang.desktop
ADD electrum_sbk.desktop /usr/share/applications/electrum_sbk.desktop
ADD 10_ubuntu-settings.gschema.override /usr/share/glib-2.0/schemas/10_ubuntu-settings.gschema.override
ADD electrum_sbk.png /opt/electrum_sbk.png
ADD watermark.png /usr/share/plymouth/themes/spinner/watermark.png
ADD watermark.png /usr/share/plymouth/ubuntu-logo.png

RUN update-initramfs -u -k all

RUN rm -rf \
    /tmp/* \
    /boot/* \
    /var/backups/* \
    /var/log/* \
    /var/run/* \
    /var/crash/* \
    /var/lib/apt/lists/* \
    ~/.bash_history

# RUN dpkg-query -W --showformat='${Installed-Size;10}\t${Package}\n' | sort -k1,1n

EOF

cat <<'EOF' > grub.cfg
if loadfont /boot/grub/font.pf2 ; then
    set gfxmode=auto
    insmod efi_gop
    insmod efi_uga
    insmod gfxterm
    terminal_output gfxterm
fi

set menu_color_normal=white/black
set menu_color_highlight=black/light-gray

set timeout=3
menuentry "SBK Live (Ubuntu 20.04 LTS)" {
    set gfxpayload=keep
    linux   /casper/vmlinuz  file=/cdrom/preseed/ubuntu.seed maybe-ubiquity quiet splash ---
    initrd  /casper/initrd
}
menuentry "SBK Live (Ubuntu 20.04 LTS - safe graphics)" {
    set gfxpayload=keep
    linux   /casper/vmlinuz  file=/cdrom/preseed/ubuntu.seed maybe-ubiquity quiet splash nomodeset ---
    initrd  /casper/initrd
}
menuentry "OEM install (for manufacturers)" {
    set gfxpayload=keep
    linux   /casper/vmlinuz  file=/cdrom/preseed/ubuntu.seed only-ubiquity quiet splash oem-config/enable=true ---
    initrd  /casper/initrd
}
grub_platform
if [ "$grub_platform" = "efi" ]; then
menuentry 'Boot from next volume' {
    exit 1
}
menuentry 'UEFI Firmware Settings' {
    fwsetup
}
fi
EOF

cat <<'EOF' > .dockerignore
filesystem*
newfilesystem*
grub.cfg
**/*.squashfs
**/*.iso
EOF

docker build -t ubuntulive:image .

# run an instance of the Docker image
CONTAINER_ID=$(docker run -d ubuntulive:image /usr/bin/tail -f /dev/null)
# delete the auto-created .dockerenv marker file so it doesn't end up in the squashfs image
docker exec "${CONTAINER_ID}" rm /.dockerenv
# extract the Docker image contents to a tarball
docker cp "${CONTAINER_ID}:/" - > newfilesystem.tar
# get the package listing for installation from ISO
docker exec "${CONTAINER_ID}" dpkg-query -W --showformat='${Package} ${Version}\n' > newfilesystem.manifest
# kill the container instance of the Docker image
docker rm -f "${CONTAINER_ID}"
# convert the image tarball into a squashfs image
tar2sqfs --quiet newfilesystem.squashfs < newfilesystem.tar

# extract the contents of the ISO to the directory, except the original squashfs image
7z x '-xr!filesystem.squashfs' -oiso "$ISO_PATH"

# copy our custom squashfs image and manifest into place
cp newfilesystem.squashfs iso/casper/filesystem.squashfs
stat --printf="%s" iso/casper/filesystem.squashfs > iso/casper/filesystem.size
cp newfilesystem.manifest iso/casper/filesystem.manifest
cp grub.cfg iso/boot/grub/grub.cfg

# update state files
(cd iso; find . -type f -print0 | xargs -0 md5sum | grep -v "\./md5sum.txt" > md5sum.txt)

# remove obsolete files
rm iso/casper/filesystem.squashfs.gpg

# build the ISO image using the image itself
docker run \
    -it \
    --rm \
    -v "$(pwd):/app" \
    ubuntulive:image \
    grub-mkrescue -o /app/ubuntulive.iso /app/iso/ -- -volid UbuntuLive

rm -f sbklive.iso
mv ubuntulive.iso sbklive.iso
