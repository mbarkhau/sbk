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

