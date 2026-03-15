SUBDIRS := callbacks ETW ppl

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	@echo "=====>> Building $@"
	@$(MAKE) --no-print-directory -C $@
	@echo ""

clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) --no-print-directory -C $$dir clean; \
	done
