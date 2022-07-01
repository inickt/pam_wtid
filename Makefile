VERSION = 2
LIBRARY_NAME = pam_wtid.so
DESTINATION = /usr/local/lib/pam
SUDO_FILE = /etc/pam.d/sudo
PAM = auth       sufficient     $(LIBRARY_NAME)
EXIST = $(shell grep -q -e "^$(PAM)" "$(SUDO_FILE)"; echo $$?)

.PHONY: all clean enable disable test test/%

all: $(LIBRARY_NAME)

clean:
	rm $(LIBRARY_NAME)

$(LIBRARY_NAME): patch.py
	python3 patch.py /usr/lib/pam/pam_tid.so.2 $(LIBRARY_NAME)
	codesign --force -s - $(LIBRARY_NAME)

install: $(LIBRARY_NAME)
	sudo mkdir -p $(DESTINATION)
	sudo install -b -o root -g wheel -m 444 $(LIBRARY_NAME) $(DESTINATION)/$(LIBRARY_NAME).$(VERSION)

enable: install
ifeq ($(EXIST), 1)
	sudo sed -E -i ".bak" "1s/^(#.*)$$/\1\n$(PAM)/" "$(SUDO_FILE)"
endif

disable:
ifeq ($(EXIST), 0)
	sudo sed -i ".bak" -e "/^$(PAM)$$/d" "$(SUDO_FILE)"
	sudo rm $(DESTINATION)/$(LIBRARY_NAME).$(VERSION)
endif

test:
	@$(foreach file, $(wildcard test/*), python3 patch.py $(file) /dev/null;)
